from datetime import datetime

from azul_plugin_office.mhtml import Parser


def test_parse_unrelated():
    """
    Test we do not treat random content as mhtml.
    """
    p = Parser(b"Quick, think of something witty to type.")
    assert not p.is_mhtml()


def test_parse_mime_doc():
    """
    Test parsing of mime document contents.
    """
    p = Parser(MIME_DOC)
    assert p.is_mhtml()
    assert p.is_mhtml_doc()
    assert not p.is_mhtml_web()

    props = p.document_properties
    assert props["Author"] == "User323"
    assert props["LastAuthor"] == "User426"
    assert props["Revision"] == 4
    assert props["TotalTime"] == 2
    assert props["Created"] == datetime(2012, 5, 1, 14, 8, 0)
    assert props["LastSaved"] == datetime(2012, 5, 1, 14, 12, 0)
    assert props["Pages"] == 44
    assert props["Words"] == 17
    assert props["Characters"] == 101
    assert props["Lines"] == 1
    assert props["Paragraphs"] == 1
    assert props["Version"] == "11.9999"

    parts = list(p.mime_parts)
    assert len(parts) == 3
    assert (
        parts[2].get_payload(decode=True)
        == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00>\x00\x03\x00\xfe\xff\t\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x10"
    )


MIME_DOC = b"""MIME-Version: 1.0
Content-Type: multipart/related; boundary="----=_NextPart_01CD27E7.8767FC40"
this document is a Single File Web Page,also known as Web archive file. if you see this message, your browser or editor does not support, please use Microsoft Internet Explorer
------=_NextPart_01CD27E7.8767FC40
Content-Location: file:///C:/23456789/Doc1.htm
Content-Transfer-Encoding: quoted-printable
Content-Type: text/html; charset="us-ascii"
<html xmlns:v=3D"urn:schemas-microsoft-com:vml"
xmlns:o=3D"urn:schemas-microsoft-com:office:office"
xmlns:w=3D"urn:schemas-microsoft-com:office:word"
xmlns=3D"http://www.w3.org/TR/REC-html40">
<head>
<meta http-equiv=3DContent-Type content=3D"text/html; charset=3Dus-ascii">
<meta name=3DProgId content=3DWord.Document>
<meta name=3DGenerator content=3D"Microsoft Word 11">
<meta name=3DOriginator content=3D"Microsoft Word 11">
<link rel=3DFile-List href=3D"Doc1.files/filelist.xml">
<link rel=3DEdit-Time-Data href=3D"Doc1.files/editdata.mso">
<!--[if !mso]>
<style>
v\\:* {behavior:url(#default#VML);}
o\\:* {behavior:url(#default#VML);}
w\\:* {behavior:url(#default#VML);}
.shape {behavior:url(#default#VML);}
</style>
<![endif]-->
<title> </title>
<!--[if gte mso 9]><xml>
 <o:DocumentProperties>
  <o:Author>User323</o:Author>
  <o:LastAuthor>User426</o:LastAuthor>
  <o:Revision>4</o:Revision>
  <o:TotalTime>2</o:TotalTime>
  <o:Created>2012-05-01T14:08:00Z</o:Created>
  <o:LastSaved>2012-05-01T14:12:00Z</o:LastSaved>
  <o:Pages>44</o:Pages>
  <o:Words>17</o:Words>
  <o:Characters>101</o:Characters>
  <o:Lines>1</o:Lines>
  <o:Paragraphs>1</o:Paragraphs>
  <o:CharactersWithSpaces>117</o:CharactersWithSpaces>
  <o:Version>11.9999</o:Version>
 </o:DocumentProperties>
</xml><![endif]--><!--[if gte mso 9]><xml>
 <w:WordDocument>
  <w:SpellingState>Clean</w:SpellingState>
  <w:GrammarState>Clean</w:GrammarState>
  <w:FormsDesign/>
  <w:PunctuationKerning/>
  <w:DrawingGridVerticalSpacing>7.8 &#30917;</w:DrawingGridVerticalSpacing>
  <w:DisplayHorizontalDrawingGridEvery>0</w:DisplayHorizontalDrawingGridEve=
  <w:DisplayVerticalDrawingGridEvery>2</w:DisplayVerticalDrawingGridEvery>
  <w:ValidateAgainstSchemas/>
  <w:SaveIfXMLInvalid>false</w:SaveIfXMLInvalid>
  <w:IgnoreMixedContent>false</w:IgnoreMixedContent>
  <w:AlwaysShowPlaceholderText>false</w:AlwaysShowPlaceholderText>
  <w:Compatibility>
   <w:SpaceForUL/>
   <w:BalanceSingleByteDoubleByteWidth/>
   <w:DoNotLeaveBackslashAlone/>
   <w:ULTrailSpace/>
   <w:DoNotExpandShiftReturn/>
   <w:AdjustLineHeightInTable/>
   <w:BreakWrappedTables/>
   <w:SnapToGridInCell/>
   <w:WrapTextWithPunct/>
   <w:UseAsianBreakRules/>
   <w:DontGrowAutofit/>
   <w:UseFELayout/>
  </w:Compatibility>
  <w:BrowserLevel>MicrosoftInternetExplorer4</w:BrowserLevel>
 </w:WordDocument>
</xml><![endif]--><!--[if gte mso 9]><xml>
 <w:LatentStyles DefLockedState=3D"false" LatentStyleCount=3D"156">
 </w:LatentStyles>
</xml><![endif]-->
<style>
<!--
 /* Font Definitions */
 @font-face
        {font-family:SimSun;
        panose-1:2 1 6 0 3 1 1 1 1 1;
        mso-font-alt:SimSun;
        mso-font-charset:134;
        mso-generic-font-family:auto;
        mso-font-pitch:variable;
        mso-font-signature:3 135135232 16 0 262145 0;}
@font-face
        {font-family:SimSun;
        panose-1:2 1 6 0 3 1 1 1 1 1;
        mso-font-charset:134;
        mso-generic-font-family:auto;
        mso-font-pitch:variable;
        mso-font-signature:3 135135232 16 0 262145 0;}
 /* Style Definitions */
 p.MsoNormal, li.MsoNormal, div.MsoNormal
        {mso-style-parent:"";
        margin:0cm;
        margin-bottom:.0001pt;
        text-align:justify;
        text-justify:inter-ideograph;
        mso-pagination:none;
        font-size:10.5pt;
        mso-bidi-font-size:12.0pt;
        font-family:"Times New Roman";
        mso-fareast-font-family:SimSun;
        mso-font-kerning:1.0pt;}
 /* Page Definitions */
 @page
        {mso-page-border-surround-header:no;
        mso-page-border-surround-footer:no;}
@page Section1
        {size:595.3pt 841.9pt;
        margin:72.0pt 90.0pt 72.0pt 90.0pt;
        mso-header-margin:42.55pt;
        mso-footer-margin:49.6pt;
        mso-paper-source:0;
        layout-grid:15.6pt;}
div.Section1
        {page:Section1;}
</style>
<!--[if gte mso 10]>
<style>
 /* Style Definitions */
 table.MsoNormalTable
        {mso-style-name:clown;
        mso-tstyle-rowband-size:0;
        mso-tstyle-colband-size:0;
        mso-style-noshow:yes;
        mso-style-parent:"";
        mso-padding-alt:0cm 5.4pt 0cm 5.4pt;
        mso-para-margin:0cm;
        mso-para-margin-bottom:.0001pt;
        mso-pagination:widow-orphan;
        font-size:10.0pt;
        font-family:"Times New Roman";
        mso-fareast-font-family:"Times New Roman";
        mso-ansi-language:#0400;
        mso-fareast-language:#0400;
        mso-bidi-language:#0400;}
</style>
<![endif]--><!--[if gte mso 9]><xml>
 <o:shapedefaults v:ext=3D"edit" spidmax=3D"1026"/>
</xml><![endif]--><!--[if gte mso 9]><xml>
 <o:shapelayout v:ext=3D"edit">
  <o:idmap v:ext=3D"edit" data=3D"1"/>
 </o:shapelayout></xml><![endif]-->
</head>
<body lang=3DZH-CN style=3D'tab-interval:21.0pt;text-justify-trim:punctuati=
on'>
<div class=3DSection1 style=3D'layout-grid:15.6pt'><span lang=3DEN-US
style=3D'font-size:10.5pt;mso-bidi-font-size:12.0pt;font-family:"Times New =
Roman";
mso-fareast-font-family:SimSun;mso-font-kerning:1.0pt;mso-ansi-language:EN-=
mso-fareast-language:ZH-CN;mso-bidi-language:AR-SA'><br clear=3Dall
style=3D'page-break-before:always'>
</span>
<p class=3DMsoNormal><span lang=3DEN-US><object
 classid=3D"CLSID:978C9E23-D4B0-11CE-BF2D-00AA003F40D0" id=3DLabel1 width=
=3D1
 height=3D1>
 <param name=3DForeColor value=3D0>
 <param name=3DBackColor value=3D16777215>
 <param name=3DCaption value=3DLabel1>
 <param name=3DSize value=3D"26;26">
 <param name=3DFontName value=3D&#23435;&#20307;>
 <param name=3DFontHeight value=3D210>
 <param name=3DFontCharSet value=3D134>
 <param name=3DFontPitchAndFamily value=3D34>
</object></span></p>
<p class=3DMsoNormal><span lang=3DEN-US><object
 classid=3D"CLSID:BDD1F04B-858B-11D1-B16A-00C0F0283628"ID= 3DShockwaveFlash1
 width=3D9 height=3D9 data=3D"dOC1.FIles/ocxSTg001.MSO"></OBJECT></span></p>
</div>
</body>
</html>
------=_NextPart_01CD27E7.8767FC40
Content-Location: file:///C:/23456789/Doc1.files/ocxstg001.mso
Content-Transfer-Encoding: base64
Content-Type: text/xml; charset
0M8R4KGxGuEAAAAAAAAAAAAAAAAAAAAAPgADAP7/CQAGAAAAAAAAAAAAAAABAAAAAQAAAAAAAAAAEA
"""
