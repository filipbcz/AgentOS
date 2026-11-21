"""Raster and malformed-image regressions; fixtures are not VM evidence."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
import zlib

SPEC = importlib.util.spec_from_file_location("console_image", Path(__file__).with_name("verify-console-image.py"))
v = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(v)


def pixels(aLines=(), aLevel="info", aOutput="both"):
    pWidth, pHeight = 640, 480
    pRgb = bytearray(b"\x18\x18\x18" * (pWidth * pHeight))
    def draw(aText, aX, aY, aScale=1):
        for pIndex, pChar in enumerate(aText):
            for pY, pRow in enumerate(v.FONT[pChar]):
                for pX in range(5):
                    if pRow & (16 >> pX):
                        for pDy in range(aScale):
                            for pDx in range(aScale):
                                pAt = ((aY+pY*aScale+pDy)*pWidth+aX+(pIndex*6+pX)*aScale+pDx)*3
                                pRgb[pAt:pAt+3] = b"\xff\xff\xff"
    draw("AGENTOS KERNEL OK STAGE 1", 8, 16, 4)
    if aLevel != "quiet" and aOutput in ("screen", "both"):
        draw("[INFO] KERNEL ENTRY", 8, 52, 2)
    for pRow, pLine in aLines:
        draw(pLine, 0, 88 + pRow*9)
    return pWidth, pHeight, bytes(pRgb)


def ppm(aImage):
    pWidth, pHeight, pRgb = aImage
    return f"P6\n{pWidth} {pHeight}\n255\n".encode() + pRgb


def png(aImage, aChannels=3, aFilter=0):
    pWidth, pHeight, pRgb = aImage
    def chunk(aKind, aBytes):
        return struct.pack(">I", len(aBytes))+aKind+aBytes+struct.pack(">I", zlib.crc32(aKind+aBytes))
    pRaw, pPrevious = bytearray(), bytes(pWidth*aChannels)
    for pY in range(pHeight):
        pRow = pRgb[pY*pWidth*3:(pY+1)*pWidth*3]
        if aChannels == 4:
            pRow = b"".join(pRow[pX:pX+3]+b"\xff" for pX in range(0,len(pRow),3))
        pRaw.append(aFilter)
        for pX,pValue in enumerate(pRow):
            pLeft = pRow[pX-aChannels] if pX>=aChannels else 0
            pUp = pPrevious[pX]
            pCorner = pPrevious[pX-aChannels] if pX>=aChannels else 0
            if aFilter == 0: pPredict = 0
            elif aFilter == 1: pPredict = pLeft
            elif aFilter == 2: pPredict = pUp
            elif aFilter == 3: pPredict = (pLeft+pUp)//2
            else:
                pEstimate = pLeft+pUp-pCorner
                pPredict = min((pLeft,pUp,pCorner), key=lambda p: abs(pEstimate-p))
            pRaw.append((pValue-pPredict)&255)
        pPrevious = pRow
    pHeader = struct.pack(">IIBBBBB",pWidth,pHeight,8,2 if aChannels==3 else 6,0,0,0)
    return b"\x89PNG\r\n\x1a\n"+chunk(b"IHDR",pHeader)+chunk(b"IDAT",zlib.compress(pRaw))+chunk(b"IEND",b"")


class ConsoleImageTests(unittest.TestCase):
    def setUp(self):
        self.fTemp = tempfile.TemporaryDirectory()
        self.addCleanup(self.fTemp.cleanup)
        self.fRoot = Path(self.fTemp.name)

    def write(self, aName, aImage):
        pPath = self.fRoot/aName
        pPath.write_bytes(ppm(aImage))
        return pPath

    def test_response_found_after_manager_prefix_at_any_complete_line(self):
        pBefore = self.write("before.ppm",pixels([(0,"AGENTOS MANAGER"),(12,"agentos> ")]))
        for pRow in (2,13,30,40):
            with self.subTest(row=pRow):
                pAfter = self.write("after.ppm",pixels([(0,"AGENTOS MANAGER"),(pRow,"ps2-ok"),(pRow+1,"agentos> ")]))
                self.assertEqual(v.verify(pAfter,pBefore,"ps2-ok","info","both"),(640,480))

    def test_echo_stale_response_and_corrupted_glyph_are_rejected(self):
        pBefore = self.write("before.ppm",pixels([(1,"agentos> ")]))
        for pLines in ([(1,"agentos> echo ps2-ok"),(2,"agentos> ")],
                       [(1,"ps2-ox"),(2,"agentos> ")],
                       [(1,"ps2-ok extra"),(2,"agentos> ")]):
            pAfter = self.write("after.ppm",pixels(pLines))
            with self.assertRaises(v.VerificationError): v.verify(pAfter,pBefore,"ps2-ok")
        pAfter = self.write("after.ppm",pixels([(1,"ps2-ok"),(2,"agentos> ")]))
        with self.assertRaises(v.VerificationError): v.verify(pAfter,pAfter,"ps2-ok")
        pDuplicate = self.write("duplicate.ppm",pixels([(1,"ps2-ok"),(2,"ps2-ok"),(3,"agentos> ")]))
        with self.assertRaises(v.VerificationError): v.verify(pDuplicate,pBefore,"ps2-ok")

    def test_retained_boot_header_checks_enabled_and_suppressed_screen_logging(self):
        for pLevel in ("quiet","info","debug"):
            for pOutput in ("none","serial","screen","both"):
                with self.subTest(level=pLevel,output=pOutput):
                    pPath = self.write("policy.ppm",pixels([(20,"agentos> ")],pLevel,pOutput))
                    self.assertEqual(v.verify(pPath,aLevel=pLevel,aOutput=pOutput),(640,480))
        pPath = self.write("leaked.ppm",pixels([(20,"agentos> ")]))
        with self.assertRaises(v.VerificationError): v.verify(pPath,aLevel="quiet",aOutput="none")
        pPath = self.write("missing.ppm",pixels([(20,"agentos> ")],"quiet","none"))
        with self.assertRaises(v.VerificationError): v.verify(pPath,aLevel="debug",aOutput="screen")

    def test_rgb_rgba_and_all_png_filters_preserve_exact_pixels(self):
        pImage = (3,3,bytes(range(27)))
        for pChannels in (3,4):
            for pFilter in range(5):
                pPath = self.fRoot/"image.png"
                pPath.write_bytes(png(pImage,pChannels,pFilter))
                pRead = v.read_image(pPath)
                self.assertEqual((pRead.fWidth,pRead.fHeight,pRead.fRgb),pImage)

    def test_truncated_bad_crc_and_unsupported_images_fail(self):
        pValid = png((2,2,b"\xff\xff\xff"*4))
        for pBytes in (pValid[:-2],pValid[:20]+b"\x01"+pValid[21:],
                       b"P6\n2 2\n255\n"+b"\xff"*11,
                       b"P6\n100000000 100000000\n255\n",b"not an image"):
            pPath = self.fRoot/"bad.png"
            pPath.write_bytes(pBytes)
            with self.assertRaises(v.VerificationError): v.read_image(pPath)

    def test_kernel_origin_contract_and_tiny_screen_fallback(self):
        self.assertEqual(v.console_origin(480),88)
        self.assertEqual(v.console_origin(100),0)
        self.assertEqual(v.console_origin(106),88)


if __name__ == "__main__": unittest.main()
