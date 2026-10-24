#!/usr/bin/env python3
"""Write the Workbench icons (.info files) for the release archive.

Usage: mkicon.py RELEASE_DIR

Writes, under RELEASE_DIR:
  RDPServer.info                    drawer icon (opens showing all files)
  RDPServer/RDPServer.info          tool icon for the program, with its
                                    options as disabled tool types
  RDPServer/RDPServer.readme.info   project icon, opened with MultiView

Classic 4-colour (2-plane) icons, readable by Workbench 2.0 and later.
Struct layouts follow workbench/workbench.h and intuition/intuition.h.
"""
import os
import struct
import sys

# Workbench palette: 0 = grey (background), 1 = black, 2 = white, 3 = blue.
DRAWER_ART = """
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk
kwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwk
kw.......................................k
kw..kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk..k
kw..kwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwk..k
kw..kw................................k..k
kw..kw................................k..k
kw..kw...........kkkkkkkkkk...........k..k
kw..kw...........kbbbbbbbbk...........k..k
kw..kw...........kkkkkkkkkk...........k..k
kw..kw................................k..k
kw..kw................................k..k
kw..kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk..k
kw.......................................k
kw.......................................k
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk
.kk....................................kk.
.kk....................................kk.
"""

# A monitor showing a Workbench screen with a window, and a two-way arrow
# below it for "remote".
TOOL_ART = """
....kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk...
....kwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwk...
....kwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwk...
....kwwkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkwwwk...
....kwwkwwwwwwwwwwwwwwwwwwwwwwwwwwwwkwwwk...
....kwwkbbbbbbbbbbbbbbbbbbbbbbbbbbbbkwwwk...
....kwwkbbbbbbbbbbbbbbbbbbbbbbbbbbbbkwwwk...
....kwwkbbkkkkkkkkkkkkkkkkkkkkkbbbbbkwwwk...
....kwwkbbkwwwwwwwwwwwwwwwwwwwkbbbbbkwwwk...
....kwwkbbkkkkkkkkkkkkkkkkkkkkkbbbbbkwwwk...
....kwwkbbk...................kbbbbbkwwwk...
....kwwkbbk...................kbbbbbkwwwk...
....kwwkbbk...................kbbbbbkwwwk...
....kwwkbbk...................kbbbbbkwwwk...
....kwwkbbkkkkkkkkkkkkkkkkkkkkkbbbbbkwwwk...
....kwwkbbbbbbbbbbbbbbbbbbbbbbbbbbbbkwwwk...
....kwwkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkwwwk...
....kwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwk...
....kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk...
.................kkkkkkkk...................
.............kkkkkkkkkkkkkkkk...............
............................................
.......kk..........................kk.......
......kbk..........................kbk......
.....kbbkkkkkkkkkkkkkkkkkkkkkkkkkkkkbbk.....
....kbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbk....
.....kbbkkkkkkkkkkkkkkkkkkkkkkkkkkkkbbk.....
......kbk..........................kbk......
.......kk..........................kk.......
"""

# A page of text with a folded corner.
README_ART = """
..kkkkkkkkkkkkkkkkkkkkkk.......
..kwwwwwwwwwwwwwwwwwwwwkk......
..kwwwwwwwwwwwwwwwwwwwwk.k.....
..kwwbbbbbbbbbbbbwwwwwwk..k....
..kwwbbbbbbbbbbbbwwwwwwkkkkk...
..kwwwwwwwwwwwwwwwwwwwwwwwwk...
..kwwkkkkkkkkkkkkkkkkkkkkwwk...
..kwwwwwwwwwwwwwwwwwwwwwwwwk...
..kwwkkkkkkkkkkkkkkkkkkwwwwk...
..kwwwwwwwwwwwwwwwwwwwwwwwwk...
..kwwkkkkkkkkkkkkkkkkkkkkwwk...
..kwwwwwwwwwwwwwwwwwwwwwwwwk...
..kwwkkkkkkkkkkkkkkwwwwwwwwk...
..kwwwwwwwwwwwwwwwwwwwwwwwwk...
..kwwkkkkkkkkkkkkkkkkkkkkwwk...
..kwwwwwwwwwwwwwwwwwwwwwwwwk...
..kwwkkkkkkkkkkkkkkkkkkkkwwk...
..kwwwwwwwwwwwwwwwwwwwwwwwwk...
..kwwkkkkkkkkkkkkkkkkwwwwwwk...
..kwwwwwwwwwwwwwwwwwwwwwwwwk...
..kwwwwwwwwwwwwwwwwwwwwwwwwk...
..kkkkkkkkkkkkkkkkkkkkkkkkkk...
"""

# The program's options, disabled (in parentheses) at their defaults, so
# they are easy to find and switch on in the icon's Information window.
TOOL_TYPES = [
    '(PORT=3389)', '(BPP=16)', '(INTERVAL=100)', '(SCAN=4)', '(NOCOMPRESS)',
    '(NOCLIPBOARD)', '(NOBEEP)', '(NEGFAIL)', '(VERBOSE)', '(QUIET)',
]

PEN = {'.': 0, 'k': 1, 'w': 2, 'b': 3}

WB_DISKMAGIC = 0xE310
WB_DISKVERSION = 1
WB_DISKREVISION = 1
WBTOOL, WBDRAWER, WBPROJECT = 3, 2, 4
NO_ICON_POSITION = 0x80000000
GFLG_GADGIMAGE_BACKFILL = 0x0005   # GFLG_GADGIMAGE | GFLG_GADGBACKFILL
GACT_RELVERIFY_IMMEDIATE = 0x0003
GTYP_BOOLGADGET = 0x0001
WBENCHSCREEN = 0x0001
DDFLAGS_SHOWALL = 2
DDVM_BYICON = 1
DEPTH = 2


def planes(rows):
    """Image data: each plane in turn, rows padded to whole 16-bit words."""
    width = len(rows[0])
    words = (width + 15) // 16
    out = bytearray()
    for plane in range(DEPTH):
        for row in rows:
            bits = 0
            for x in range(words * 16):
                pen = PEN[row[x]] if x < width else 0
                bits = (bits << 1) | ((pen >> plane) & 1)
            out += bits.to_bytes(words * 2, 'big')
    return bytes(out)


def icon(art, objtype, default_tool=None, stack=0, tooltypes=()):
    """The bytes of a .info file with one image."""
    rows = art.strip('\n').split('\n')
    width, height = len(rows[0]), len(rows)
    assert all(len(r) == width for r in rows), 'ragged icon art'
    drawer = objtype == WBDRAWER

    gadget = struct.pack('>IhhhhHHHIIIiIHI',
                         0,                     # NextGadget
                         0, 0, width, height,   # LeftEdge, TopEdge, Width, Height
                         GFLG_GADGIMAGE_BACKFILL, GACT_RELVERIFY_IMMEDIATE,
                         GTYP_BOOLGADGET,
                         1,                     # GadgetRender: an image follows
                         0, 0, 0, 0,            # SelectRender, GadgetText, MutualExclude, SpecialInfo
                         0,                     # GadgetID
                         WB_DISKREVISION)       # UserData: icon revision
    out = struct.pack('>HH', WB_DISKMAGIC, WB_DISKVERSION) + gadget + \
        struct.pack('>BBIIIIIIi',
                    objtype, 0,
                    1 if default_tool else 0,   # DefaultTool follows
                    1 if tooltypes else 0,      # ToolTypes follow
                    NO_ICON_POSITION, NO_ICON_POSITION,
                    1 if drawer else 0,         # DrawerData follows
                    0,                          # ToolWindow
                    stack)
    assert len(out) == 78

    if drawer:
        # OldDrawerData: the drawer window's NewWindow, then dd_CurrentX/Y
        out += struct.pack('>hhhhBBIIIIIIIhhHHH',
                           50, 30, 400, 120,    # LeftEdge, TopEdge, Width, Height
                           0xff, 0xff,          # DetailPen, BlockPen
                           0, 0,                # IDCMPFlags, Flags
                           0, 0, 0, 0, 0,       # FirstGadget, CheckMark, Title, Screen, BitMap
                           90, 40, 0xffff, 0xffff,
                           WBENCHSCREEN)
        out += struct.pack('>ii', 0, 0)

    out += struct.pack('>hhhhhIBBI',
                       0, 0, width, height, DEPTH,
                       1,                       # ImageData follows
                       (1 << DEPTH) - 1, 0,     # PlanePick, PlaneOnOff
                       0)                       # NextImage
    out += planes(rows)

    def string(text):
        b = text.encode('latin-1') + b'\0'
        return struct.pack('>I', len(b)) + b

    if default_tool:
        out += string(default_tool)
    if tooltypes:
        # the size of the NULL-terminated pointer array, then the strings
        out += struct.pack('>I', 4 * (len(tooltypes) + 1))
        for t in tooltypes:
            out += string(t)

    if drawer:
        # DrawerData's OS 2.0 fields, present because the revision is non-zero
        out += struct.pack('>IH', DDFLAGS_SHOWALL, DDVM_BYICON)
    return out


def main(root):
    icons = {
        'RDPServer.info': icon(DRAWER_ART, WBDRAWER),
        'RDPServer/RDPServer.info': icon(TOOL_ART, WBTOOL, stack=65536, tooltypes=TOOL_TYPES),
        'RDPServer/RDPServer.readme.info':
            icon(README_ART, WBPROJECT, default_tool='SYS:Utilities/MultiView', stack=8192),
    }
    for name, data in icons.items():
        with open(os.path.join(root, name), 'wb') as f:
            f.write(data)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
