"""Verify real VirtualBox PNG / QEMU PPM console pixels using only stdlib.

The glyph asset comes from the shipped kernel font. Text is checked against
actual captured pixels; no guest output or success marker is synthesized.
Console responses must occupy a whole text line and be absent before input,
so the command echo or an unrelated changed pixel cannot satisfy the check.
"""
import argparse
import ast
from pathlib import Path
import re
import struct
import sys
import zlib

ROOT = Path(__file__).resolve().parents[1]
MAX_PIXELS = 16 * 1024 * 1024


class VerificationError(ValueError):
    pass


def require(aCondition, aMessage):
    if not aCondition:
        raise VerificationError(aMessage)


class Image:
    def __init__(self, aWidth, aHeight, aRgb):
        require(0 < aWidth * aHeight <= MAX_PIXELS, "Invalid screenshot size")
        require(len(aRgb) == aWidth * aHeight * 3, "Truncated screenshot pixels")
        self.fWidth, self.fHeight, self.fRgb = aWidth, aHeight, aRgb

    def white(self, aX, aY):
        pOffset = (aY * self.fWidth + aX) * 3
        return all(pValue > 200 for pValue in self.fRgb[pOffset:pOffset + 3])


def load_font():
    pSource = (ROOT / "kernel/fb_console.rs").read_text(encoding="utf-8")
    pFont = {}
    for pLiteral, pValues in re.findall(r"(b'(?:\\.|[^'])')\s*=>\s*\[([0-9, ]+)\]", pSource):
        pByte = ast.literal_eval(pLiteral)
        pRows = tuple(int(pValue) for pValue in pValues.split(","))
        if len(pByte) == 1 and len(pRows) == 7 and all(0 <= pRow < 32 for pRow in pRows):
            pFont[chr(pByte[0])] = pRows
    # The compact Rust [0; 7] entry for space has no foreground pixels.
    pFont[" "] = (0,) * 7
    require(all(pChar in pFont for pChar in "AGENTOS KERNEL OK STAGE 1[INFO]agentos>ps2-ok"),
            "Kernel font asset is incomplete or changed format")
    return pFont


FONT = load_font()


def console_origin(aHeight):
    pSource = (ROOT / "kernel/fb_console.rs").read_text(encoding="utf-8")
    pMatch = re.search(r"pub const BOOT_STATUS_HEIGHT:\s*usize\s*=\s*(\d+)", pSource)
    require(pMatch is not None, "Kernel does not define the retained boot status band")
    pHeight = int(pMatch[1])
    return pHeight if aHeight >= pHeight + 18 else 0


def _paeth(aLeft, aUp, aUpperLeft):
    pEstimate = aLeft + aUp - aUpperLeft
    pLeft, pUp, pCorner = (abs(pEstimate - pValue) for pValue in (aLeft, aUp, aUpperLeft))
    return aLeft if pLeft <= pUp and pLeft <= pCorner else aUp if pUp <= pCorner else aUpperLeft


def _png(aData):
    pOffset, pHeader, pChunks, pEnded = 8, None, [], False
    while pOffset + 12 <= len(aData):
        pLength = int.from_bytes(aData[pOffset:pOffset + 4], "big")
        pKind = aData[pOffset + 4:pOffset + 8]
        pEnd = pOffset + 12 + pLength
        require(pEnd <= len(aData), "Truncated PNG chunk")
        pPayload = aData[pOffset + 8:pEnd - 4]
        require(zlib.crc32(pKind + pPayload) & 0xffffffff ==
                int.from_bytes(aData[pEnd - 4:pEnd], "big"), "PNG checksum mismatch")
        if pKind == b"IHDR":
            require(pHeader is None and pOffset == 8 and pLength == 13, "Invalid PNG header")
            pHeader = struct.unpack(">IIBBBBB", pPayload)
        elif pKind == b"IDAT":
            require(pHeader is not None, "PNG pixels before header")
            pChunks.append(pPayload)
        elif pKind == b"IEND":
            require(pLength == 0 and pEnd == len(aData), "Invalid PNG end")
            pEnded = True
            break
        elif pKind[:1].isupper() and pKind != b"PLTE":
            raise VerificationError("Unsupported critical PNG chunk")
        pOffset = pEnd
    require(pHeader is not None and pEnded and pChunks, "Incomplete PNG")
    pWidth, pHeight, pDepth, pColor, pCompression, pFilter, pInterlace = pHeader
    require(pWidth > 0 and pHeight > 0 and pWidth * pHeight <= MAX_PIXELS,
            "Invalid PNG dimensions")
    require(pDepth == 8 and pColor in (2, 6) and
            pCompression == pFilter == pInterlace == 0,
            "Screenshot must be noninterlaced 8-bit RGB/RGBA PNG")
    pChannels = 3 if pColor == 2 else 4
    pStride = pWidth * pChannels
    pExpected = pHeight * (pStride + 1)
    pDecoder = zlib.decompressobj()
    try:
        pDecoded = pDecoder.decompress(b"".join(pChunks), pExpected + 1)
    except zlib.error as pError:
        raise VerificationError("Invalid compressed PNG pixels") from pError
    require(len(pDecoded) == pExpected and pDecoder.eof and
            not pDecoder.unused_data and not pDecoder.unconsumed_tail,
            "Invalid PNG decompressed size")
    pRgb, pPrevious = bytearray(), bytearray(pStride)
    for pY in range(pHeight):
        pOffset = pY * (pStride + 1)
        pMethod = pDecoded[pOffset]
        require(pMethod <= 4, "Unknown PNG row filter")
        pRow = bytearray(pDecoded[pOffset + 1:pOffset + 1 + pStride])
        for pX in range(pStride):
            pLeft = pRow[pX - pChannels] if pX >= pChannels else 0
            pUp = pPrevious[pX]
            pCorner = pPrevious[pX - pChannels] if pX >= pChannels else 0
            pPrediction = (0, pLeft, pUp, (pLeft + pUp) // 2,
                           _paeth(pLeft, pUp, pCorner))[pMethod]
            pRow[pX] = (pRow[pX] + pPrediction) & 255
        if pChannels == 3:
            pRgb.extend(pRow)
        else:
            for pX in range(0, pStride, 4):
                require(pRow[pX + 3] == 255, "Screenshot has transparent pixels")
                pRgb.extend(pRow[pX:pX + 3])
        pPrevious = pRow
    return Image(pWidth, pHeight, bytes(pRgb))


def read_image(aPath):
    pData = Path(aPath).read_bytes()
    require(len(pData) <= 80 * 1024 * 1024, "Screenshot exceeds capture limit")
    if pData.startswith(b"\x89PNG\r\n\x1a\n"):
        return _png(pData)
    # QEMU screendump emits binary RGB PPM. Consume only its exact header,
    # never strip leading whitespace from the binary pixel array.
    pMatch = re.match(rb"P6\s+([0-9]+)\s+([0-9]+)\s+255(?:\r\n|\n)", pData)
    require(pMatch is not None, "Unsupported screenshot format (PNG/P6 PPM required)")
    return Image(int(pMatch[1]), int(pMatch[2]), pData[pMatch.end():])


def match_text(aImage, aText, aX, aY, aScale=1, aBackground=True):
    if aX < 0 or aY < 0 or aX + len(aText) * 6 * aScale > aImage.fWidth or aY + 7 * aScale > aImage.fHeight:
        return False
    for pIndex, pChar in enumerate(aText):
        require(pChar in FONT, f"Unsupported glyph {pChar!r}")
        for pY, pRow in enumerate(FONT[pChar]):
            for pX in range(6):
                pExpected = pX < 5 and bool(pRow & (16 >> pX))
                if not aBackground and not pExpected:
                    continue
                for pDy in range(aScale):
                    for pDx in range(aScale):
                        if aImage.white(aX + (pIndex * 6 + pX) * aScale + pDx,
                                        aY + pY * aScale + pDy) != pExpected:
                            return False
    return True


def text_rows(aImage, aText, aWholeLine=False):
    pRows = []
    for pY in range(console_origin(aImage.fHeight), aImage.fHeight - 8, 9):
        if not match_text(aImage, aText, 0, pY):
            continue
        if aWholeLine and any(aImage.white(pX, pY + pDy)
                             for pX in range(len(aText) * 6, aImage.fWidth)
                             for pDy in range(7)):
            continue
        pRows.append(pY)
    return pRows


def verify(aAfter, aBefore=None, aResponse=None, aLevel=None, aOutput=None):
    pAfter = read_image(aAfter)
    require(text_rows(pAfter, "agentos> "), "No complete live shell prompt in GOP")
    if aLevel is not None or aOutput is not None:
        require(aLevel in ("quiet", "info", "debug") and
                aOutput in ("none", "serial", "screen", "both"), "Invalid boot screen policy")
        require(console_origin(pAfter.fHeight) > 0, "VM screen too small for retained boot evidence")
        pText = "AGENTOS KERNEL OK STAGE 1"
        pScale = max(1, min(4, (pAfter.fWidth - 16) // (len(pText) * 6)))
        require(match_text(pAfter, pText, 8, 16, pScale, False), "Boot identity missing from retained GOP header")
        pScale = max(1, min(2, (pAfter.fWidth - 16) // 240))
        pVisible = match_text(pAfter, "[INFO] KERNEL ENTRY", 8, 52, pScale)
        pExpected = aLevel in ("info", "debug") and aOutput in ("screen", "both")
        require(pVisible == pExpected, "Retained GOP BOOT.LOG visibility violates configured policy")
    if aResponse is not None:
        require(aBefore is not None, "Response verification needs the preceding screenshot")
        pBefore = read_image(aBefore)
        require((pBefore.fWidth, pBefore.fHeight) == (pAfter.fWidth, pAfter.fHeight),
                "Screenshot geometry changed during keyboard test")
        require(not text_rows(pBefore, aResponse, True), "Expected keyboard response was already visible before input")
        require(len(text_rows(pAfter, aResponse, True)) == 1,
                "Missing or ambiguous whole-line keyboard response pixels")
    return pAfter.fWidth, pAfter.fHeight


def main():
    pParser = argparse.ArgumentParser(description=__doc__)
    pParser.add_argument("--after", type=Path, required=True)
    pParser.add_argument("--before", type=Path)
    pParser.add_argument("--response")
    pParser.add_argument("--level", choices=("quiet", "info", "debug"))
    pParser.add_argument("--output", choices=("none", "serial", "screen", "both"))
    pArgs = pParser.parse_args()
    try:
        pSize = verify(pArgs.after, pArgs.before, pArgs.response, pArgs.level, pArgs.output)
    except (OSError, VerificationError, ValueError) as pError:
        print(f"Console image verification failed: {pError}", file=sys.stderr)
        return 1
    print(f"Verified actual GOP pixels {pSize[0]}x{pSize[1]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
