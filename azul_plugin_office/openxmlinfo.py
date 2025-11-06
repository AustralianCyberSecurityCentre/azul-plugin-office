"""MS Office 2007+ XML Zip Parser.

Extracts properties and metadata from Microsoft Office Open XML documents
(.docx, .xlsx, etc.).  This includes features to help analysis and correlation
of documents during malware analysis like ActiveX and VBA Macro details.
"""

import sys
import zipfile
from contextlib import contextmanager
from datetime import datetime
from pprint import pprint

try:
    from zipfile import BadZipFile
except ImportError:
    from zipfile import BadZipfile as BadZipFile

import click
import defusedxml.ElementTree as et
from defusedxml import (
    DefusedXmlException,
    DTDForbidden,
    EntitiesForbidden,
    ExternalReferenceForbidden,
)

BOOL_PROPS = [
    "ScaleCrop",
    "SharedDoc",
    "HyperlinksChanged",
    "LinksUpToDate",
]
INTEGER_PROPS = [
    "TotalTime",
    "Pages",
    "Words",
    "Characters",
    "CharactersWithSpaces",
    "Lines",
    "Paragraphs",
    "DocSecurity",
    "HiddenSlides",
    "MMClips",
    "Notes",
    "Slides",
    "revision",
]
DATETIME_PROPS = [
    "created",
    "modified",
    "lastPrinted",
]


def parse(handle):
    """Parse an ooxml zip from the supplied content.

    @param handle: File-like object to read zip content.
    @return: Dict containing metadata and status.
    """
    try:
        meta = {"parsing": "valid"}
        with _managed_zip(handle) as zp:
            for n in zp.namelist():
                for k, f in HANDLER_FUNCS.items():
                    if k in n:
                        f(meta, zp.read(n), n)
        return meta

    except BadZipFile:
        return {"parsing": "invalid"}


@contextmanager
def _managed_zip(*args, **kwargs):
    """Context manager for opening and releasing zipfiles."""
    zp = zipfile.ZipFile(*args, **kwargs)
    try:
        yield zp
    finally:
        zp.close()


def _parse_xml(meta, content, name):
    """Parse the supplied xml content.

    Parsing errors or detected abuses are stored as 'warnings' in meta.

    @param meta: Dict to store any warnings into.
    @param props: Byte string of xml to parse.
    @param name: Label name to include in warnings.
    @return: An `ElementTree.Element` representing the root node or None.
    """
    try:
        return et.fromstring(content, forbid_dtd=True)
    # propbably overkill but try to detect any potentially
    # malicious tampering of the xml content
    except ExternalReferenceForbidden:
        meta.setdefault("warnings", []).append("%s_contains_external_ref" % name)
    except EntitiesForbidden:
        meta.setdefault("warnings", []).append("%s_contains_entities" % name)
    except DTDForbidden:
        meta.setdefault("warnings", []).append("%s_contains_dtd" % name)
    except DefusedXmlException:
        meta.setdefault("warnings", []).append("%s_invalid" % name)
    return None


def handle_app_props(meta, props, fname=None):
    """Parse the Open Office XML docProps/app.xml content, adding to meta.

    @param meta: Dictionary to store metadata in.
    @param props: Byte string of file contents to parse.
    @param fname: Filename the content is from.
    """
    properties = _parse_xml(meta, props, "app_xml")
    if not properties:
        return

    app_props = {}
    meta["app_props"] = app_props

    # no way to specify namespace mapping when iterating?
    # just strip {} portion from tag names
    for child in properties:
        tag = child.tag.split("}")[-1]
        # special handling for some types
        if tag == "HeadingPairs":
            app_props["HeadingPairs"] = []
            for x in child.iter():
                if x.tag.endswith("lpstr"):
                    heading = x.text or ""
                if x.tag.endswith("i4"):
                    count = int(x.text)
                    app_props["HeadingPairs"].append({"part": heading, "count": count})
        elif tag == "TitlesOfParts":
            app_props["TitlesOfParts"] = []
            for x in child.iter():
                if x.tag.endswith("lpstr") and x.text:
                    app_props["TitlesOfParts"].append(x.text)
        # no idea what actually populates this field
        # but it is set with valid urls in some documents
        elif tag == "HLinks":
            app_props["HLinks"] = []
            for x in child.iter():
                if not x.text:
                    continue
                if x.tag.endswith("lpstr") or x.tag.endswith("lpwstr"):
                    app_props["HLinks"].append(x.text)

        elif child.text:
            f = lambda x: x  # noqa: E731
            if tag in BOOL_PROPS:
                f = _to_bool
            elif tag in INTEGER_PROPS:
                f = int
            elif tag in DATETIME_PROPS:
                f = _parse_isodate
            app_props[tag] = f(child.text)


def _to_bool(s):
    """Convert str to bool, handling several representations.

    @param s: String to convert.
    @return: bool representation of string.
    """
    if s.lower() in ["false", "no", "0"]:
        return False
    return True


def _parse_isodate(ts):
    """Parse the supplied timestamp.

    Inbuilt datetime is terrible at timezone info.
    This only really works correctly for py3 where tz info is preserved.

    @param ts: Timestamp string
    @return: `datetime.datetime` object (timezone aware, py2.7 naive)
    """
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    if sys.version_info[0] == 2:
        return datetime.strptime(ts[:-6], "%Y-%m-%dT%H:%M:%S")
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S%z")


def handle_content_types(meta, content, fname=None):
    """Parse the Office Open XML [Content_Types].xml file.

    @param meta: Dictionary to store metadata in.
    @param content: XML content of [Content_Types].xml file.
    @param fname: Filename the content is from.
    """
    types = _parse_xml(meta, content, "content_types_xml")
    if not types:
        return

    for child in types:
        if not child.get("Extension"):
            continue
        meta.setdefault("content_types", []).append(
            {
                "extension": child.get("Extension"),
                "content_type": child.get("ContentType"),
            }
        )


def handle_core_props(meta, props, fname=None):
    """Parse the Office Open XML docProps/core.xml content, adding to meta.

    @param meta: Dictionary to store metadata in.
    @param props: Byte string of file contents to parse.
    @param fname: Filename the content is from.
    """
    properties = _parse_xml(meta, props, "core_xml")
    if not properties:
        return
    core_props = {}
    meta["core_props"] = core_props

    for child in properties:
        tag = child.tag.split("}")[-1]
        if child.text:
            f = lambda x: x  # noqa: E731
            if tag in BOOL_PROPS:
                f = _to_bool
            elif tag in INTEGER_PROPS:
                f = int
            elif tag in DATETIME_PROPS:
                f = _parse_isodate
            core_props[tag] = f(child.text)


def handle_custom_props(meta, props, fname=None):
    """Parse any Office Open XML docProps/custom.xml content.

    This may need more attention to get anything useful as custom
    properties often contain their own definitions/schemas.

    @param meta: Dictionary to store metadata in.
    @param props: Byte string of file contents to parse.
    @param fname: Filename the content is from.
    """
    properties = _parse_xml(meta, props, "custom_xml")
    if not properties:
        return
    custom_props = {}
    meta["custom_props"] = custom_props

    for child in properties:
        tag = child.tag.split("}")[-1]
        if child.text:
            custom_props[tag] = child.text


def handle_macro(meta, content, fname):
    """Record details about macros found in the document.

    @param meta: Dictionary to store metadata in.
    @param content: Macro content as byte string.
    @param fname: Filename the content is from.
    """
    if not fname.endswith(".bin"):
        return

    meta.setdefault("vba_macros", []).append(fname)


def handle_activex(meta, content, fname):
    """Extract details about referenced ActiveX objects in the document.

    @param meta: Dictionary to store metadata in.
    @param content: Content of ActiveX related file.
    @param fname: Filename the content is from.
    """
    # ignore the bin files for now
    if "xml" not in fname:
        return

    # use the filename id as a way to link meta from multiple file types
    ref = int(fname.split("activeX")[-1].split(".")[0])
    rec = None
    for r in meta.setdefault("activex_objects", []):
        if r["id"] == ref:
            rec = r
            break
    if not rec:
        rec = {"id": ref}
        meta["activex_objects"].append(rec)

    if fname.endswith(".xml"):
        # single tag file
        xml = _parse_xml(meta, content, "activex_xml")
        if xml is None:
            return
        for k, v in xml.items():
            if k.endswith("classid"):
                rec["classid"] = v
            if k.endswith("persistence"):
                rec["persistence"] = v

    elif fname.endswith(".rels"):
        rels = _parse_xml(meta, content, "activex_xml_rels")
        if not rels:
            return
        for child in rels.iter():
            tag = child.tag.split("}")[-1]
            if tag != "Relationship":
                continue
            rec["target"] = child.get("Target")


def handle_media(meta, content, fname):
    """Record metadata about included media files in the document.

    @param meta: Dictionary to store metadata in.
    @param content: Media file content.
    @param fname: Filename the content is from.
    """
    meta.setdefault("media_objects", []).append(fname)


def handle_embedded(meta, content, fname):
    """Record metadata about any embedded object files in the document.

    This includes content like legacy ole2 content.

    @param meta: Dictionary to store metadata in.
    @param content: Embedded object content.
    @param fname: Filename the content is from.
    """
    meta.setdefault("embedded_objects", []).append(fname)


def handle_doc(meta, content, fname=None):
    """Handle main document.xml and extract metadata.

    @param meta: Dictionary to store metadata in.
    @param content: Document XML content.
    @param fname: Filename the content is from.
    """
    doc = _parse_xml(meta, content, "document_xml")
    if not doc:
        return
    for child in doc.iter():
        tag = child.tag.split("}")[-1]
        if tag == "lang":
            meta.setdefault("languages", set()).update({x.lower() for x in child.attrib.values()})


def handle_workbook(meta, content, fname=None):
    """Handle xl workbook.xml and extract metadata.

    @param meta: Dictionary to store metadata in.
    @param content: Workbook.xml content.
    @param fname: Filename the content is from.
    """
    wb = _parse_xml(meta, content, "workbook_xml")
    if not wb:
        return
    meta.setdefault("workbook", {})
    for child in wb.iter():
        tag = child.tag.split("}")[-1]
        if tag == "absPath" and child.get("url"):
            meta["workbook"].setdefault("alternate_content", []).append(child.get("url"))

        elif tag == "fileVersion":
            meta["workbook"]["lastEdited"] = child.get("lastEdited")
            meta["workbook"]["lowestEdited"] = child.get("lowestEdited")
            meta["workbook"]["rupBuild"] = child.get("rupBuild")

        elif tag == "sheets":
            meta["workbook"]["sheets"] = len(child)

        elif tag == "revisionPtr":
            for k, v in child.items():
                k = k.split("}")[-1]
                if k in ["revIDLastSave", "coauthVersionLast", "coauthVersionMax", "revIDLastSave"]:
                    v = int(v)
                meta["workbook"][k] = v

        elif tag == "calcPr":
            meta["workbook"]["calcPr"] = int(child.get("calcId"))


def handle_rels(meta, content, fname=None):
    """Handle rels mappings and extract features like external hyperlinks.

    @param meta: Dictionary to store metadata in.
    @param content: XML content of the rels file.
    @param fname: Filename the content is from.
    """
    rels = _parse_xml(meta, content, "rels")
    if not rels:
        return
    for child in rels.iter():
        tag = child.tag.split("}")[-1]
        if tag == "Relationship":
            # do we only care about external refs?
            if child.get("TargetMode") != "External":
                continue
            # strip off the url prefix to get the last path elem
            # should be something like 'hyperlink' or 'image'
            reltype = child.get("Type")
            if reltype:
                reltype = reltype.split("/")[-1]
            meta.setdefault("relationships", []).append(
                {"id": child.get("Id"), "type": reltype, "target": child.get("Target")}
            )


def handle_printers(meta, content, fname=None):
    """Handle printerSettings stored in some doc files.

    Extracts any embedded printer names.

    @param meta: Dictionary to store metadata into.
    @param content: printerSettingsX.bin content.
    @param fname: Filename the content is from.
    """
    # printerSettings.bin generated on windows
    # is a DEVMODEA struct, just grab the printer
    # name for this usage. It's the first field.
    p = content[:64].rstrip(b"\0")
    if b"\0" in p:
        # oops utf16-le encoded, put back last byte
        p += b"\0"
        p = p.decode("utf-16")
    else:
        p = p.decode("utf-8")
    meta.setdefault("printers", set()).add(p)


# filename substrings to handler func
HANDLER_FUNCS = {
    "[Content_Types].xml": handle_content_types,
    "docProps/app.xml": handle_app_props,
    "docProps/core.xml": handle_core_props,
    "docProps/custom.xml": handle_custom_props,
    "/vbaProject": handle_macro,
    "/activeX": handle_activex,
    "/media/": handle_media,
    "/embeddings": handle_embedded,
    "document.xml": handle_doc,
    "workbook.xml": handle_workbook,
    ".rels": handle_rels,
    "printerSettings": handle_printers,
}


@click.command()
@click.argument("filename", nargs=-1)
def main(filename: tuple[str]):
    """Process the list of files, printing metadata to stdout."""
    for f in filename:
        print("-" * 30)
        print(f)
        print("-" * 30)
        try:
            pprint(parse(open(f, "rb")))
        except Exception as ex:
            print(ex)
