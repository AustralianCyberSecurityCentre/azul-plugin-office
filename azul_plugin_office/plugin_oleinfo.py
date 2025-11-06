"""OLE Info Plugin.

This plugin publishes features extracted from OLE documents.

.. note::

    MS Office files 2007+ (eg docx, xlsx) are not OLE files and not
    processed by this tool.
"""

from hashlib import sha256
from tempfile import NamedTemporaryFile

import olefile
from azul_runner import Feature, FeatureType, Job, State, add_settings, cmdline_run
from oletools import oleid

from .template import DocumentInfo

TRUNCATE_LENGTH = 100


class AzulPluginOleInfo(DocumentInfo):
    """Runs various tools from oletools suite to extract metadata from OLE files."""

    VERSION = "2025.03.19"
    SETTINGS = add_settings(
        filter_data_types={
            "content": [
                "document/office/word",
                "document/office/excel",
                "document/office/powerpoint",
                "installer/windows",
                "document/office/visio",
                "document/office/ole",
            ]
        },
    )

    FEATURES = [
        # Also includes inherited feature outputs from DocumentInfo class
        Feature(name="ole_title", desc="OLE document title", type=FeatureType.String),
        Feature(
            name="ole_codepage", desc="Codepage specified by the SummaryInformation stream", type=FeatureType.Integer
        ),
        Feature(
            name="ole_codepage_doc",
            desc="Codepage specified by the DocumentSummaryInformation stream",
            type=FeatureType.Integer,
        ),
        Feature(name="ole_subject", desc="OLE document subject", type=FeatureType.String),
        Feature(name="ole_author", desc="Author of the OLE document", type=FeatureType.String),
        Feature(name="ole_keywords", desc="Any keywords set for the OLE document", type=FeatureType.String),
        Feature(name="ole_comments", desc="Any comments set for the OLE document", type=FeatureType.String),
        Feature(name="ole_template", desc="Name of the template used in the OLE document", type=FeatureType.String),
        Feature(name="ole_saved_by", desc="Name of user who last saved the document", type=FeatureType.String),
        Feature(name="ole_revision", desc="Revision number of the OLE document", type=FeatureType.String),
        Feature(
            name="ole_edit_duration",
            desc="Total time the document has been edited in minutes",
            type=FeatureType.Integer,
        ),
        Feature(name="ole_time_printed", desc="Time document was last printed", type=FeatureType.Datetime),
        Feature(name="ole_time_created", desc="Time document was created", type=FeatureType.Datetime),
        Feature(name="ole_time_saved", desc="Time document was last saved", type=FeatureType.Datetime),
        Feature(name="ole_count_chars", desc="Number of characters in OLE document", type=FeatureType.Integer),
        Feature(name="ole_count_flash", desc="Number of flash objects in OLE document", type=FeatureType.Integer),
        Feature(name="ole_count_words", desc="Number of words in OLE document", type=FeatureType.Integer),
        Feature(name="ole_count_pages", desc="Number of pages in OLE document", type=FeatureType.Integer),
        Feature(name="ole_count_lines", desc="Number of lines in OLE document", type=FeatureType.Integer),
        Feature(name="ole_count_paragraphs", desc="Number of paragraphs in OLE document", type=FeatureType.Integer),
        Feature(name="ole_count_slides", desc="Number of slides in powerpoint document", type=FeatureType.Integer),
        Feature(name="ole_count_notes", desc="Number of notes in OLE document", type=FeatureType.Integer),
        Feature(
            name="ole_count_hidden_slides", desc="Number of hidden slides in OLE document", type=FeatureType.Integer
        ),
        Feature(name="ole_count_clips", desc="Number of clips in OLE document", type=FeatureType.Integer),
        Feature(name="ole_thumbnail_hash", desc="SHA256 of OLE document thumbnail", type=FeatureType.String),
        Feature(name="ole_application", desc="Application used to create OLE document", type=FeatureType.String),
        Feature(name="ole_security", desc="OLE document security", type=FeatureType.String),
        Feature(name="ole_category", desc="OLE document categories", type=FeatureType.String),
        Feature(name="ole_presentation_target", desc="Powerpoint presentation target", type=FeatureType.String),
        Feature(name="ole_manager", desc="OLE document manager", type=FeatureType.String),
        Feature(name="ole_company", desc="OLE document authors company name", type=FeatureType.String),
        Feature(name="ole_language", desc="Language set for the OLE document", type=FeatureType.String),
        Feature(name="ole_signature", desc="Digital signatures present in the OLE document", type=FeatureType.String),
        Feature(name="ole_content_status", desc="Status of document content", type=FeatureType.String),
        Feature(name="ole_version", desc="OLE document version number", type=FeatureType.Integer),
        Feature(name="ole_contains", desc="Tags showing objects the OLE document contains", type=FeatureType.String),
        Feature(name="ole_error", desc="OLE formatting errors", type=FeatureType.String),
    ]

    _FEATURE_TYPES = dict([(feature.name, feature.type) for feature in FEATURES + list(DocumentInfo.FEATURES)])

    def execute(self, job: Job):
        """Run oletools to extract metadata from binary's data.

        Opt out if unable to identfy as ole file.
        """
        features = {}
        # despite oletools accepting a bytes str we use filename as there
        # are still bugs present which cause some samples to throw attribute
        # errors due to references to .name for arg
        with NamedTemporaryFile(delete=True) as tmp:
            # only read first portion of file for magic checks
            # we can't check buffer directly as, if less than 1500 bytes,
            # oletools thinks its a filename...
            data = job.get_data()
            tmp.write(data.read(2048))
            tmp.flush()

            # only execute on OLE files
            if not olefile.isOleFile(tmp.name):
                return State.Label.OPT_OUT

            # stream rest of file for analysis
            tmp.write(data.read())
            tmp.flush()

            indicators = []
            meta = {}
            try:
                # open OLE file and get indicators
                ole = oleid.OleID(tmp.name)
                indicators = ole.check()
                # get ole metadata
                ole = olefile.OleFileIO(tmp.name)
                meta = ole.get_metadata()
            except Exception as err:
                # save parse errors as features
                features["ole_error"] = str(err)
                self.add_many_feature_values(features)

            for indicator in indicators:
                # value can be True, False, int or None
                if indicator.name in CONTAINS_MAPPINGS and self._variable_boolean(indicator.value):
                    value = CONTAINS_MAPPINGS[indicator.name]
                    features.setdefault("ole_contains", []).append(value)
                elif indicator.name in TAG_MAPPINGS and indicator.value:
                    value = TAG_MAPPINGS[indicator.name]
                    features.setdefault("tag", []).append(value)
                # map some of the counts to specific features
                if indicator.name in OLEMETA_FEAT_MAPPINGS and indicator.value:
                    features[OLEMETA_FEAT_MAPPINGS[indicator.name]] = int(indicator.value)

            # normal features
            for name, feats in OLEMETA_FEAT_MAPPINGS.items():
                value = getattr(meta, name, None)
                if not value:
                    continue
                # returns byte strings we want str
                if type(value) is bytes:
                    try:
                        value = value.decode("utf-8")
                    except UnicodeDecodeError:
                        # Some files appear to use symbols in 8-bit space (not UTF-8/16)
                        # - handle these:
                        value = value.decode("iso-8859-1")
                # can map to multiple features
                if type(feats) is not list:
                    feats = [feats]

                # Security is an enum:
                # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-oleps/f7933d28-2cc4-4b36-bc23-8861cbcd37c4?redirectedfrom=MSDN
                if name == "security":
                    try:
                        value = SECURITY_MAPPING[int(value)]
                    except ValueError:
                        value = "Invalid security mapping: " + str(value)

                for x in feats:
                    # Cast types to the types they are expected to be - typing information
                    # from OLE can be inconsistent, so we need to normalise this.
                    # String in particular will always be VtStrings (see openspec link above),
                    # so trying to treat these conditionally as integers doesn't make sense.
                    if self._FEATURE_TYPES[x] == FeatureType.String:
                        features[x] = str(value)
                    else:
                        features[x] = value

            # add in actual hash of thumbnail if value present
            thumbnail = getattr(meta, "thumbnail", None)
            if thumbnail is not None:
                thumbnail_hash = sha256(thumbnail).hexdigest()
                features["ole_thumbnail_hash"] = thumbnail_hash

            # boolean features -> tags
            for name, tag in TAG_MAPPINGS.items():
                # value can be True, False or None
                if getattr(meta, name, None):
                    features.setdefault("tag", []).append(tag)
            for name, tag in CONTAINS_MAPPINGS.items():
                if getattr(meta, name, None):
                    features.setdefault("ole_contains", []).append(tag)

            # save any errors that were raised
            for name in ("summaryerror", "docsummaryerror"):
                err = getattr(meta, name, None)
                if err:
                    features.setdefault("ole_error", []).append(err)

        # Truncate certain values that should always be short but can be long if there is lots of bad unicode.
        feats_to_truncate = ["ole_application", "ole_revision"]
        for feat in feats_to_truncate:
            if len(features.get(feat, [])) > TRUNCATE_LENGTH:
                features[feat] = features[feat][:TRUNCATE_LENGTH]

        self.add_many_feature_values(features)

    def _variable_boolean(self, val):
        """Return True if positive indicator value.

        Handles inconsistencies in ole indicators where a mix of values
        are present, including bools, strings and ints (counts).
        """
        if val in (True, "Yes"):
            return True
        if isinstance(val, int) and val:
            return True
        return False


# feature mappings
OLEMETA_FEAT_MAPPINGS = {
    "codepage": "ole_codepage",
    "title": ["ole_title", "document_title"],
    "subject": "ole_subject",
    "author": ["ole_author", "document_author"],
    "keywords": "ole_keywords",
    "comments": "ole_comments",
    "template": "ole_template",
    "last_saved_by": ["ole_saved_by", "document_last_author"],
    "revision_number": "ole_revision",
    "total_edit_time": "ole_edit_duration",
    "last_printed": "ole_time_printed",
    "create_time": ["ole_time_created", "document_created"],
    "last_saved_time": ["ole_time_saved", "document_last_saved"],
    "num_pages": ["ole_count_pages", "document_page_count"],
    "num_words": ["ole_count_words", "document_word_count"],
    "num_chars": "ole_count_chars",
    "creating_application": "ole_application",
    "security": "ole_security",
    "codepage_doc": "ole_codepage_doc",
    "category": "ole_category",
    "presentation_target": "ole_presentation_target",
    "lines": "ole_count_lines",
    "paragraphs": "ole_count_paragraphs",
    "slides": "ole_count_slides",
    "notes": "ole_count_notes",
    "hidden_slides": "ole_count_hidden_slides",
    "mm_clips": "ole_count_clips",
    "manager": "ole_manager",
    "company": ["ole_company", "document_company"],
    "version": "ole_version",
    "content_status": "ole_content_status",
    "language": "ole_language",
    "Flash objects": "ole_count_flash",
}


CONTAINS_MAPPINGS = {
    "dig_sig": "DIGITAL_SIGNATURE",
    "VBA Macros": "VBA_MACROS",
    "XLM Macros": "XLM_MACROS",
    "ObjectPool": "OLE_OBJECTS",
    "Flash objects": "FLASH_OBJECTS",
}


TAG_MAPPINGS = {
    "scale_crop": "SCALE_CROPPED",
    "links_dirty": "LINKS_DIRTY",
    "shared_doc": "SHARED_DOC",
    "hlinks_changed": "HLINKS_CHANGED",
    "Encrypted": "ENCRYPTED",
    "External Relationships": "EXTERNAL_LINKS",
}

SECURITY_MAPPING = {
    0x00: "No security",
    0x01: "Password protected",
    0x02: "Read-only recommended",
    0x04: "Read-only enforced",
    0x08: "Locked for annotations",
}


def main():
    """Run plugin via command-line."""
    cmdline_run(plugin=AzulPluginOleInfo)


if __name__ == "__main__":
    main()
