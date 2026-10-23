#!/usr/bin/env python3
"""Write the RDPServer drawer icon (a Workbench .info file).

Usage: mkicon.py OUTPUT.info

A classic 4-colour (2-plane) drawer icon, readable by Workbench 2.0 and later.
The drawer opens showing all files, since the files inside have no icons.
Struct layouts follow workbench/workbench.h and intuition/intuition.h.
"""
import struct
import sys

# Workbench palette: 0 = grey (background), 1 = black, 2 = white, 3 = blue.
# A monitor showing a Workbench screen with a window, and a two-way arrow
# below it for "remote".
ART = """
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

PEN = {'.': 0, 'k': 1, 'w': 2, 'b': 3}

WB_DISKMAGIC = 0xE310
WB_DISKVERSION = 1
WB_DISKREVISION = 1
WBDRAWER = 2
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


def main(path):
    rows = ART.strip('\n').split('\n')
    width, height = len(rows[0]), len(rows)
    assert all(len(r) == width for r in rows), 'ragged icon art'

    gadget = struct.pack('>IhhhhHHHIIIiIHI',
                         0,                     # NextGadget
                         0, 0, width, height,   # LeftEdge, TopEdge, Width, Height
                         GFLG_GADGIMAGE_BACKFILL, GACT_RELVERIFY_IMMEDIATE,
                         GTYP_BOOLGADGET,
                         1,                     # GadgetRender: an image follows
                         0, 0, 0, 0,            # SelectRender, GadgetText, MutualExclude, SpecialInfo
                         0,                     # GadgetID
                         WB_DISKREVISION)       # UserData: icon revision
    diskobj = struct.pack('>HH', WB_DISKMAGIC, WB_DISKVERSION) + gadget + \
        struct.pack('>BBIIIIIIi',
                    WBDRAWER, 0,
                    0, 0,                       # DefaultTool, ToolTypes
                    NO_ICON_POSITION, NO_ICON_POSITION,
                    1,                          # DrawerData follows
                    0, 0)                       # ToolWindow, StackSize
    assert len(diskobj) == 78

    # OldDrawerData: the drawer window's NewWindow, then dd_CurrentX/Y
    newwindow = struct.pack('>hhhhBBIIIIIIIhhHHH',
                            50, 30, 400, 120,   # LeftEdge, TopEdge, Width, Height
                            0xff, 0xff,         # DetailPen, BlockPen
                            0, 0,               # IDCMPFlags, Flags
                            0, 0, 0, 0, 0,      # FirstGadget, CheckMark, Title, Screen, BitMap
                            90, 40, 0xffff, 0xffff,
                            WBENCHSCREEN)
    olddrawer = newwindow + struct.pack('>ii', 0, 0)
    assert len(olddrawer) == 56

    image = struct.pack('>hhhhhIBBI',
                        0, 0, width, height, DEPTH,
                        1,                      # ImageData follows
                        (1 << DEPTH) - 1, 0,    # PlanePick, PlaneOnOff
                        0)                      # NextImage
    assert len(image) == 20

    # DrawerData's OS 2.0 fields, present because the revision is non-zero
    drawer2 = struct.pack('>IH', DDFLAGS_SHOWALL, DDVM_BYICON)

    with open(path, 'wb') as f:
        f.write(diskobj + olddrawer + image + planes(rows) + drawer2)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
