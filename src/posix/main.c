/*
 * Linux/POSIX host for the RDP server prototype.
 *
 * Serves the animated test pattern (testpattern.c, standing in for an Amiga
 * screen) so a client such as mstsc can be checked end to end.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "../rdp.h"
#include "../testpattern.h"
#include "hostkey.h"

static int net_send(void *ctx, const uint8_t *data, size_t len)
{
    int fd = *(int *)ctx;
    while (len) {
        ssize_t n = send(fd, data, len, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        data += n; len -= (size_t)n;
    }
    return 0;
}

static int net_recv(void *ctx, uint8_t *data, size_t len)
{
    int fd = *(int *)ctx;
    while (len) {
        ssize_t n = recv(fd, data, len, 0);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        data += n; len -= (size_t)n;
    }
    return 0;
}

static void get_random(void *ctx, uint8_t *out, size_t len)
{
    FILE *f = fopen("/dev/urandom", "rb");
    (void)ctx;
    if (!f || fread(out, 1, len, f) != len) {
        perror("/dev/urandom");
        exit(1);
    }
    fclose(f);
}

static void log_msg(void *ctx, const char *msg)
{
    struct timeval tv;
    (void)ctx;
    gettimeofday(&tv, NULL);
    printf("[%ld.%03ld] %s\n", (long)tv.tv_sec % 1000, (long)tv.tv_usec / 1000, msg);
    fflush(stdout);
}

/* Returns 1 if the client gave up after wrong passwords. */
static int serve(int fd, const rdp_config *cfg)
{
    rdp_callbacks cb = { 0 };
    rdp_session *sess;
    struct timeval next, now;
    int failed;

    cb.ctx = &fd;
    cb.send = net_send;
    cb.recv = net_recv;
    cb.random = get_random;
    cb.log = log_msg;
    tp_set_callbacks(&cb);

    sess = rdp_session_new(cfg, &cb);
    if (!sess) {
        fprintf(stderr, "bad configuration\n");
        exit(1);
    }
    tp_reset(sess);
    rdp_clipboard_changed(sess);    /* offer the pattern's clipboard */
    gettimeofday(&next, NULL);
    for (;;) {
        fd_set rfds;
        struct timeval tmo;
        long us;

        gettimeofday(&now, NULL);
        us = (next.tv_sec - now.tv_sec) * 1000000L + (next.tv_usec - now.tv_usec);
        if (us < 0) us = 0;
        tmo.tv_sec = us / 1000000L; tmo.tv_usec = us % 1000000L;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        if (select(fd + 1, &rfds, NULL, NULL, &tmo) < 0 && errno != EINTR)
            break;
        if (FD_ISSET(fd, &rfds) && rdp_session_process(sess))
            break;
        {
            int nw, nh;
            if (tp_resize_requested(&nw, &nh) &&
                (tp_resize(nw, nh) || rdp_session_resize(sess, nw, nh, tp_fb(), 0)))
                break;
        }
        gettimeofday(&now, NULL);
        if (now.tv_sec > next.tv_sec || (now.tv_sec == next.tv_sec && now.tv_usec >= next.tv_usec)) {
            next.tv_usec += 50000;      /* 20 fps */
            if (next.tv_usec >= 1000000) { next.tv_sec++; next.tv_usec -= 1000000; }
            if (rdp_session_active(sess))
                tp_animate();
        }
        if (rdp_flush(sess))
            break;
    }
    failed = rdp_session_auth_failed(sess);
    rdp_session_free(sess);
    tp_reset(NULL);
    return failed;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s (-P password | -n) [-p port] [-b 8|15|16|24|32] [-W width] [-H height] [-u] [-k] [-f] [-v]\n"
            "  -P   password clients must enter (or send as saved credentials)\n"
            "  -n   no password: anyone who can connect gets control\n"
            "  -u   send bitmaps uncompressed (default: RLE where the depth allows)\n"
            "  -k   generate a fresh server key at startup (default: the build's key)\n"
            "  -f   refuse TLS with RDP_NEG_FAILURE (xrdp style) instead of\n"
            "       answering RDP_NEG_RSP with PROTOCOL_RDP\n"
            "  -v   verbose protocol logging\n", argv0);
    exit(2);
}

int main(int argc, char **argv)
{
    rdp_config cfg = { 0 };
    int port = 3389, lfd, opt, one = 1, w = 640, h = 512, nopass = 0, newkey = 0;
    struct sockaddr_in addr;

    cfg.bpp = 16;
    while ((opt = getopt(argc, argv, "p:b:W:H:fvP:nuk")) != -1) {
        switch (opt) {
        case 'k': newkey = 1; break;
        case 'u': cfg.no_compress = 1; break;
        case 'P': cfg.password = optarg; break;
        case 'n': nopass = 1; break;
        case 'p': port = atoi(optarg); break;
        case 'b': cfg.bpp = atoi(optarg); break;
        case 'W': w = atoi(optarg) & ~3; break;
        case 'H': h = atoi(optarg); break;
        case 'f': cfg.neg_fail = 1; break;
        case 'v': cfg.verbose = 1; break;
        default: usage(argv[0]);
        }
    }
    if (!cfg.password == !nopass) {
        fprintf(stderr, "give a password with -P, or -n to run without one\n");
        usage(argv[0]);
    }
    if (tp_init(w, h)) {                /* the test pattern's layout needs this */
        fprintf(stderr, "minimum size is 640x400\n");
        usage(argv[0]);
    }
    cfg.width = w; cfg.height = h;
    cfg.fb = tp_fb(); cfg.palette = tp_palette();

    if (newkey) {
        uint8_t n[64], d[64];
        uint32_t e;
        if (rdp_generate_server_key(n, d, &e, get_random, NULL) || rdp_set_server_key(n, d, e)) {
            fprintf(stderr, "key generation failed\n");
            return 1;
        }
        printf("generated a new server key\n");
    } else if (rdp_set_server_key(host_key_modulus, host_key_privexp, host_key_exponent)) {
        fprintf(stderr, "bad server key\n");
        return 1;
    }

    lfd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (lfd < 0 || bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) || listen(lfd, 4)) {
        perror("listen");
        return 1;
    }
    printf("listening on port %d (%dx%d, %d bpp, %s, %s)\n", port, w, h, cfg.bpp,
           cfg.neg_fail ? "refuse TLS with RDP_NEG_FAILURE" : "select PROTOCOL_RDP",
           cfg.password ? "password required" : "NO PASSWORD");
    fflush(stdout);

    for (;;) {
        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        int fd = accept(lfd, (struct sockaddr *)&peer, &plen);
        if (fd < 0)
            continue;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        printf("=== connection from %s:%d\n", inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));
        if (serve(fd, &cfg)) {
            close(fd);
            printf("=== connection closed after wrong passwords; pausing\n");
            fflush(stdout);
            sleep(2);               /* slow down password guessing */
            continue;
        }
        close(fd);
        printf("=== connection closed\n");
        fflush(stdout);
    }
}
