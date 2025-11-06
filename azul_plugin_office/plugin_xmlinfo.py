"""Open XML Info Plugin.

This plugin publishes features extracted from MS Office 2007+ files.
"""

import traceback
import zipfile

from azul_runner import (
    Feature,
    FeatureType,
    FeatureValue,
    Job,
    State,
    add_settings,
    cmdline_run,
)
from pydantic import TypeAdapter, ValidationError
from pydantic.networks import HttpUrl

from . import openxmlinfo
from .template import DocumentInfo

httpUrlValidator = TypeAdapter(HttpUrl)


class AzulPluginOpenXmlInfo(DocumentInfo):
    """Runs openxmlinfo parser across the content and returns any corresponding features."""

    VERSION = "2025.03.19"

    SETTINGS = add_settings(
        filter_data_types={
            "content": [
                "document/office/unknown",
                "document/xml",  # for open document
                "document/odt/",
                "document/office/word",
                "document/office/powerpoint",
                "document/office/excel",
            ]
        },
    )
    FEATURES = [
        # Also includes inherited feature outputs from DocumentInfo class
        # [Content_Types].xml fields
        Feature(name="openxml_content_type", desc="Content type/exts stored in the document", type=FeatureType.String),
        # docProps/app.xml fields
        Feature(name="openxml_application", desc="Application used to create the document", type=FeatureType.String),
        Feature(
            name="openxml_application_version",
            desc="Version of application used to create document",
            type=FeatureType.String,
        ),
        Feature(
            name="openxml_heading_part", desc="Document parts from HeadingPairs property", type=FeatureType.String
        ),
        Feature(
            name="openxml_heading_part_count",
            desc="Document part counts from HeadingPairs property",
            type=FeatureType.Integer,
        ),
        Feature(
            name="openxml_part_title", desc="Document part titles from TitlesOfParts property", type=FeatureType.String
        ),
        Feature(name="openxml_template", desc="Template recorded in properties", type=FeatureType.String),
        Feature(name="openxml_company", desc="Company name as recorded in properties", type=FeatureType.String),
        Feature(name="openxml_manager", desc="Manager of the Open XML document author", type=FeatureType.String),
        Feature(name="openxml_security", desc="DocSecurity setting from properties", type=FeatureType.Integer),
        Feature(name="openxml_prop_hyperlink", desc="HLink item from document properties", type=FeatureType.Uri),
        Feature(
            name="openxml_count_chars", desc="Count of chars in document, from properties", type=FeatureType.Integer
        ),
        Feature(
            name="openxml_count_lines", desc="Count of lines in document, from properties", type=FeatureType.Integer
        ),
        Feature(
            name="openxml_count_pages", desc="Count of pages in document, from properties", type=FeatureType.Integer
        ),
        Feature(
            name="openxml_count_paragraphs",
            desc="Count of paragraphs in document, from properties",
            type=FeatureType.Integer,
        ),
        Feature(
            name="openxml_count_words", desc="Count of words in document, from properties", type=FeatureType.Integer
        ),
        Feature(name="openxml_count_slides", desc="Count of slides in presentation", type=FeatureType.Integer),
        Feature(
            name="openxml_count_hidden_slides", desc="Count of hidden slides in presentation", type=FeatureType.Integer
        ),
        Feature(
            name="openxml_count_mmclips", desc="Count of multimedia clips in presentation", type=FeatureType.Integer
        ),
        Feature(name="openxml_count_notes", desc="Count of notes in presentation", type=FeatureType.Integer),
        Feature(
            name="openxml_presentation_format",
            desc="Display format for powerpoint presentation",
            type=FeatureType.String,
        ),
        Feature(name="openxml_edit_duration", desc="Time spent editing document in minutes", type=FeatureType.Integer),
        Feature(name="openxml_flag", desc="Properties flags set to true in the document", type=FeatureType.String),
        # docProps/core.xml fields
        Feature(name="openxml_creator", desc="Author of the Open XML document", type=FeatureType.String),
        Feature(name="openxml_modified_by", desc="Last user to modify the Open XML document", type=FeatureType.String),
        Feature(name="openxml_time_created", desc="Time the Open XML document was created", type=FeatureType.Datetime),
        Feature(
            name="openxml_time_modified", desc="Time the Open XML document was last saved", type=FeatureType.Datetime
        ),
        Feature(
            name="openxml_time_printed", desc="Time the Open XML document was last printed", type=FeatureType.Datetime
        ),
        Feature(name="openxml_revision", desc="Revision number of the Open XML document", type=FeatureType.Integer),
        Feature(name="openxml_title", desc="Title of the Open XML document", type=FeatureType.String),
        Feature(
            name="openxml_description",
            desc="Description included in the Open XML document props",
            type=FeatureType.String,
        ),
        Feature(
            name="openxml_subject", desc="Subject included in the Open XML document props", type=FeatureType.String
        ),
        Feature(
            name="openxml_keywords", desc="Keywords included in the Open XML document props", type=FeatureType.String
        ),
        # relationships from .rels
        Feature(
            name="openxml_external_link", desc="Document relationships with external target", type=FeatureType.String
        ),
        Feature(
            name="openxml_external_link_type",
            desc="External relationship types in the document",
            type=FeatureType.String,
        ),
        # languages from document.xml
        Feature(
            name="openxml_language",
            desc="Any language attributes extracted from main document",
            type=FeatureType.String,
        ),
        # workbook metadata
        Feature(
            name="openxml_alternate_content_path", desc="Excel AlternateContent absPath", type=FeatureType.Filepath
        ),
        Feature(name="openxml_alternate_content_url", desc="Excel AlternateContent absPath url", type=FeatureType.Uri),
        Feature(
            name="openxml_version_lowest_edited", desc="Workbook lowest edited version info", type=FeatureType.String
        ),
        Feature(name="openxml_version_last_edited", desc="Workbook last edited version info", type=FeatureType.String),
        Feature(
            name="openxml_version_build",
            desc="Workbook incremental public release version info",
            type=FeatureType.String,
        ),
        Feature(name="openxml_count_sheets", desc="Count of sheets in workbook", type=FeatureType.Integer),
        Feature(
            name="openxml_calc_properties_id", desc="Calculation properties Id in workbook", type=FeatureType.Integer
        ),
        Feature(
            name="openxml_revision_uid_last_save", desc="Workbook revision lastSavedUid field", type=FeatureType.String
        ),
        Feature(
            name="openxml_revision_document_id", desc="Workbook revision documentId field", type=FeatureType.String
        ),
        # other objects
        Feature(
            name="openxml_activex_classid", desc="ActiveX classid referenced in document", type=FeatureType.String
        ),
        Feature(
            name="openxml_activex_objects",
            desc="Count of ActiveX objects contained in document",
            type=FeatureType.Integer,
        ),
        Feature(
            name="openxml_macro_objects", desc="Count of macro objects contained in document", type=FeatureType.Integer
        ),
        Feature(
            name="openxml_embedded_objects", desc="Count of embedded objects in document", type=FeatureType.Integer
        ),
        Feature(
            name="openxml_ole2_objects", desc="Count of embedded ole2 objects in document", type=FeatureType.Integer
        ),
        Feature(
            name="openxml_media_objects", desc="Count of media files contained in document", type=FeatureType.Integer
        ),
        Feature(
            name="openxml_flash_objects", desc="Count of flash objects contained in document", type=FeatureType.Integer
        ),
        # printer devices
        Feature(name="openxml_printer", desc="Printer device names extracted from document", type=FeatureType.String),
        # Very suspicious file
        Feature(
            name="openxml_failed_to_extract",
            desc="Flag to indicate a file failed to extract and it's possibly not an openxml doc.",
            type=FeatureType.String,
        ),
        Feature("corrupted", desc="A corrupted file that could not be analyzed.", type=FeatureType.String),
    ]

    def execute(self, job: Job):
        """Run openxmlinfo to extract metadata from ooxml document data."""
        data = job.get_data()
        try:
            meta = openxmlinfo.parse(data)
        except OSError:
            if zipfile.is_zipfile(data):
                zip_file = zipfile.ZipFile(data)
                self.add_feature_values("openxml_failed_to_extract", "File is zip and extraction failed.")
                file_names = [cur_file.filename for cur_file in zip_file.filelist]
                is_ooxml = set(["[Content_Types].xml", "_rels/.rels"]).issubset(file_names)
                if is_ooxml:
                    self.add_feature_values("corrupted", f"Suspicious file contains '{len(file_names)}' files.")
            else:
                self.add_feature_values("openxml_failed_to_extract", "Not a zip file and not an openxml.")
            return State(
                State.Label.COMPLETED_WITH_ERRORS,
                message=f"Corrupted file either it's malicious or there's a bug {traceback.format_exc()}",
            )

        # app.xml
        for field, value in meta.get("app_props", {}).items():
            for f in XML_FEAT_MAPPINGS.get(field, []):
                self.add_feature_values(f, value)
            if type(value) is bool and value:
                self.add_feature_values("openxml_flag", field)

        # core.xml
        for field, value in meta.get("core_props", {}).items():
            for f in XML_FEAT_MAPPINGS.get(field, []):
                self.add_feature_values(f, value)

        # workbook info
        for field, value in meta.get("workbook", {}).items():
            for f in XML_FEAT_MAPPINGS.get(field, []):
                self.add_feature_values(f, value)

        # top level propertes
        for field, value in meta.items():
            for f in XML_FEAT_MAPPINGS.get(field, []):
                self.add_feature_values(f, value)

        # Labelled features and special cases...
        for c in meta.get("content_types", []):
            self.add_feature_values(
                "openxml_content_type",
                FeatureValue(c["extension"], label=c["content_type"]),
            )
            if c["extension"] == "swf":
                self.add_feature_values("tag", "openxml_contains_flash")

        if meta.get("app_props", {}).get("Application") and meta.get("app_props", {}).get("AppVersion"):
            self.add_feature_values(
                "openxml_application_version",
                FeatureValue(meta["app_props"]["AppVersion"], label=meta["app_props"]["Application"]),
            )

        # heading pairs
        for hp in meta.get("app_props", {}).get("HeadingPairs", []):
            self.add_feature_values("openxml_heading_part", hp["part"])
            self.add_feature_values(
                "openxml_heading_part_count",
                FeatureValue(hp["count"], label=hp["part"]),
            )

        # Property HLinks
        for f in meta.get("app_props", {}).get("HLinks", []):
            try:
                # Validate URL before adding it
                httpUrlValidator.validate_python(f)
                self.add_feature_values("openxml_prop_hyperlink", f)
            except ValidationError:
                pass

        # titles of parts
        for t in meta.get("app_props", {}).get("TitlesOfParts", []):
            self.add_feature_values("openxml_part_title", t)

        # external targeted rels
        for rel in meta.get("relationships", []):
            self.add_feature_values("openxml_external_link_type", rel["type"])
            self.add_feature_values("openxml_external_link", FeatureValue(rel["target"], label=rel["type"]))

        if meta.get("vba_macros"):
            self.add_feature_values("openxml_macro_objects", len(meta["vba_macros"]))
            self.add_feature_values("tag", "openxml_contains_macros")

        if meta.get("embedded_objects"):
            self.add_feature_values("openxml_embedded_objects", len(meta["embedded_objects"]))
            self.add_feature_values("tag", "openxml_contains_embedded_objects")
            ole = [x for x in meta["embedded_objects"] if "oleObject" in x]
            if ole:
                self.add_feature_values("openxml_ole2_objects", len(ole))
                self.add_feature_values("tag", "openxml_contains_ole2_objects")

        if meta.get("media_objects"):
            self.add_feature_values("openxml_media_objects", len(meta["media_objects"]))
            # will file ext be accurate?
            flash = [x for x in meta["media_objects"] if x.endswith(".swf")]
            if flash:
                self.add_feature_values("openxml_flash_objects", len(flash))
                self.add_feature_values("tag", "openxml_contains_flash")

        for a in meta.get("activex_objects", []):
            self.add_feature_values("openxml_activex_classid", a["classid"])

        if meta.get("activex_objects"):
            self.add_feature_values("openxml_activex_objects", len(meta["activex_objects"]))
            self.add_feature_values("tag", "openxml_contains_activex")

        # known heap spray optimisation (make multiple refs point to same .bin)
        bins = len({x["target"] for x in meta.get("activex_objects", [])})
        if bins < len(meta.get("activex_objects", [])):
            self.add_feature_values("tag", "openxml_reused_activex_bins")

        # excel workbook fields
        for a in meta.get("workbook", {}).get("alternate_content", []):
            try:
                # Add as a URL unless it isn't a URL so it must be a content path.
                httpUrlValidator.validate_python(a)
                self.add_feature_values("openxml_alternate_content_url", a)
            except ValidationError:
                self.add_feature_values("openxml_alternate_content_path", a)

        for w in meta.get("warnings", []):
            self.add_feature_values("tag", w)


# feature mappings
XML_FEAT_MAPPINGS = {
    "Application": ["openxml_application"],
    "Characters": ["openxml_count_chars"],
    "Company": ["openxml_company", "document_company"],
    "Manager": ["openxml_manager"],
    "DocSecurity": ["openxml_security"],
    "Lines": ["openxml_count_lines"],
    "Pages": ["openxml_count_pages", "document_page_count"],
    "Paragraphs": ["openxml_count_paragraphs"],
    "Template": ["openxml_template"],
    "TotalTime": ["openxml_edit_duration"],
    "HiddenSlides": ["openxml_count_hidden_slides"],
    "Slides": ["openxml_count_slides"],
    "MMClips": ["openxml_count_mmclips"],
    "Notes": ["openxml_count_notes"],
    "PresentationFormat": ["openxml_presentation_format"],
    "Words": ["openxml_count_words", "document_word_count"],
    "title": ["openxml_title", "document_title"],
    "description": ["openxml_description"],
    "keywords": ["openxml_keywords"],
    "subject": ["openxml_subject"],
    "creator": ["openxml_creator", "document_author"],
    "lastModifiedBy": ["openxml_modified_by", "document_last_author"],
    "revision": ["openxml_revision"],
    "lastPrinted": ["openxml_time_printed"],
    "created": ["openxml_time_created", "document_created"],
    "modified": ["openxml_time_modified", "document_last_saved"],
    "languages": ["openxml_language"],
    "language": ["openxml_language"],
    "printers": ["openxml_printer"],
    "rupBuild": ["openxml_version_build"],
    "lastEdited": ["openxml_version_last_edited"],
    "lowestEdited": ["openxml_version_lowest_edited"],
    "calcPr": ["openxml_calc_properties_id"],
    "sheets": ["openxml_count_sheets"],
    "uidLastSave": ["openxml_revision_uid_last_save"],
    "documentId": ["openxml_revision_document_id"],
}


def main():
    """Run plugin via command-line."""
    cmdline_run(plugin=AzulPluginOpenXmlInfo)


if __name__ == "__main__":
    main()
