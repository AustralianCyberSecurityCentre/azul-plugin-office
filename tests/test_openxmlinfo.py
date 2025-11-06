import datetime
import os
import sys
import unittest

from azul_runner.test_utils import FileManager

from azul_plugin_office import openxmlinfo

# py2.7 compat
try:
    from io import BytesIO
except ImportError:
    from StringIO import StringIO as BytesIO


class TestOpenXmlInfo(unittest.TestCase):
    def test_app_props(self):
        m = {}
        openxmlinfo.handle_app_props(m, APP_PROPS_XML)
        self.assertEqual(APP_PROPS_RESULT, m)

    def test_core_props(self):
        m = {}
        openxmlinfo.handle_core_props(m, CORE_PROPS_XML)
        self.assertEqual(CORE_PROPS_RESULT, m)

    def test_printer_settings(self):
        m = {}
        openxmlinfo.handle_printers(m, PRINT_SETTINGS_BIN)
        self.assertEqual(PRINT_SETTINGS_RESULT, m)

    def test_parse(self):
        fm = FileManager()
        # Malicious Microsoft Open XML document.
        b = fm.download_file_bytes("034fded5914cdd2eed99c5fb8c6076821370804b96307775b9d23f60cb11b670")
        m = openxmlinfo.parse(BytesIO(b))
        self.assertEqual(DOCX_RESULT, m)

    def test_workbook(self):
        m = {}
        openxmlinfo.handle_workbook(m, WORKBOOK_XML)
        self.assertEqual(WORKBOOK_RESULT, m)


APP_PROPS_XML = b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"><Template>Normal</Template><TotalTime>90</TotalTime><Pages>3</Pages><Words>803</Words><Characters>3941</Characters><Application>Microsoft Office Word</Application><DocSecurity>0</DocSecurity><Lines>80</Lines><Paragraphs>32</Paragraphs><ScaleCrop>false</ScaleCrop><HeadingPairs><vt:vector size="2" baseType="variant"><vt:variant><vt:lpstr>hello</vt:lpstr></vt:variant><vt:variant><vt:i4>1</vt:i4></vt:variant></vt:vector></HeadingPairs><TitlesOfParts><vt:vector size="1" baseType="lpstr"><vt:lpstr></vt:lpstr></vt:vector></TitlesOfParts><Company>Ministry of Fun</Company><LinksUpToDate>false</LinksUpToDate><CharactersWithSpaces>4745</CharactersWithSpaces><SharedDoc>false</SharedDoc><HyperlinksChanged>false</HyperlinksChanged><AppVersion>14.0000</AppVersion></Properties>'

APP_PROPS_RESULT = {
    "app_props": {
        "Template": "Normal",
        "TotalTime": 90,
        "Pages": 3,
        "Words": 803,
        "Characters": 3941,
        "Application": "Microsoft Office Word",
        "DocSecurity": 0,
        "Lines": 80,
        "Paragraphs": 32,
        "ScaleCrop": False,
        "HeadingPairs": [{"part": "hello", "count": 1}],
        "TitlesOfParts": [],
        "Company": "Ministry of Fun",
        "LinksUpToDate": False,
        "CharactersWithSpaces": 4745,
        "SharedDoc": False,
        "HyperlinksChanged": False,
        "AppVersion": "14.0000",
    }
}

CORE_PROPS_XML = b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>A Malware Analysts Adventure</dc:title><dc:creator>Lee T</dc:creator><cp:lastModifiedBy>Win7</cp:lastModifiedBy><cp:revision>12</cp:revision><dcterms:created xsi:type="dcterms:W3CDTF">2018-03-13T16:57:00Z</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">2018-03-13T18:34:00Z</dcterms:modified></cp:coreProperties>'
if sys.version_info[0] == 2:
    CORE_PROPS_RESULT = {
        "core_props": {
            "title": "A Malware Analysts Adventure",
            "creator": "Lee T",
            "lastModifiedBy": "Win7",
            "revision": 12,
            "created": datetime.datetime(2018, 3, 13, 16, 57),
            "modified": datetime.datetime(2018, 3, 13, 18, 34),
        }
    }
else:
    CORE_PROPS_RESULT = {
        "core_props": {
            "title": "A Malware Analysts Adventure",
            "creator": "Lee T",
            "lastModifiedBy": "Win7",
            "revision": 12,
            "created": datetime.datetime(2018, 3, 13, 16, 57, tzinfo=datetime.timezone.utc),
            "modified": datetime.datetime(2018, 3, 13, 18, 34, tzinfo=datetime.timezone.utc),
        }
    }

PRINT_SETTINGS_BIN = b"H\x00P\x00 \x00L\x00J\x002\x004\x002\x000\x00 \x00V\x00a\x00t\x00h\x00a\x00m\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x04\x00\x06\xdc\x00\xec\x1dC\xff\x80\x07\x01\x00\x01\x00\xea\no\x08d\x00\x01\x00\x0f\x00X\x02\x02\x00\x01\x00X\x02\x03\x00"  # truncated deliberately

PRINT_SETTINGS_RESULT = {"printers": {"HP LJ2420 Vatham"}}

DOCX_RESULT = {
    "parsing": "valid",
    "languages": {"ru-ru"},
    "content_types": [
        {"extension": "bin", "content_type": "application/vnd.ms-office.vbaProject"},
        {"extension": "jpeg", "content_type": "image/jpeg"},
        {"extension": "rels", "content_type": "application/vnd.openxmlformats-package.relationships+xml"},
        {"extension": "xml", "content_type": "application/xml"},
    ],
    "vba_macros": ["word/vbaProject.bin"],
    "media_objects": ["word/media/image1.jpeg"],
    "app_props": {
        "Template": "Normal.dotm",
        "TotalTime": 5914,
        "Pages": 2,
        "Words": 0,
        "Characters": 2,
        "Application": "Microsoft Office Word",
        "DocSecurity": 0,
        "Lines": 1,
        "Paragraphs": 1,
        "ScaleCrop": False,
        "HeadingPairs": [
            {"part": b"\xd0\x9d\xd0\xb0\xd0\xb7\xd0\xb2\xd0\xb0\xd0\xbd\xd0\xb8\xd0\xb5".decode("utf-8"), "count": 1}
        ],
        "TitlesOfParts": [],
        "LinksUpToDate": False,
        "CharactersWithSpaces": 2,
        "SharedDoc": False,
        "HyperlinksChanged": False,
        "AppVersion": "14.0000",
    },
    "core_props": {
        "creator": "7",
        "lastModifiedBy": b"\xd0\x9f\xd0\xbe\xd0\xbb\xd1\x8c\xd0\xb7\xd0\xbe\xd0\xb2\xd0\xb0\xd1\x82\xd0\xb5\xd0\xbb\xd1\x8c Windows".decode(
            "utf-8"
        ),
        "revision": 102,
        "created": datetime.datetime(2020, 3, 11, 13, 24),
        "modified": datetime.datetime(2020, 3, 16, 14, 29),
    },
}

# naive timestamps on py2 with tzinfo on py3
if sys.version_info[0] > 2:
    DOCX_RESULT["core_props"]["created"] = datetime.datetime(2020, 3, 11, 13, 24, tzinfo=datetime.timezone.utc)
    DOCX_RESULT["core_props"]["modified"] = datetime.datetime(2020, 3, 16, 14, 29, tzinfo=datetime.timezone.utc)

WORKBOOK_XML = b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" mc:Ignorable="x15" xmlns:x15="http://schemas.microsoft.com/office/spreadsheetml/2010/11/main"><fileVersion appName="xl" lastEdited="7" lowestEdited="5" rupBuild="18201"/><workbookPr defaultThemeVersion="124226"/><mc:AlternateContent xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"><mc:Choice Requires="x15"><x15ac:absPath url="G:\\Life Sciences R&amp;D Credit Program" xmlns:x15ac="http://schemas.microsoft.com/office/spreadsheetml/2010/11/ac"/></mc:Choice></mc:AlternateContent><bookViews><workbookView xWindow="0" yWindow="180" windowWidth="23250" windowHeight="11865" activeTab="1"/></bookViews><sheets><sheet name="Employment" sheetId="2" r:id="rId1"/><sheet name="Qualified Expenses" sheetId="3" r:id="rId2"/><sheet name="related persons" sheetId="4" r:id="rId3"/></sheets><calcPr calcId="171027"/></workbook>'

WORKBOOK_RESULT = {
    "workbook": {
        "lastEdited": "7",
        "lowestEdited": "5",
        "rupBuild": "18201",
        "alternate_content": ["G:\\Life Sciences R&D Credit Program"],
        "sheets": 3,
        "calcPr": 171027,
    }
}
