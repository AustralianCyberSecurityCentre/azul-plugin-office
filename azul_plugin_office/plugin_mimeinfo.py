"""Mime HTML Info Plugin.

This plugin detects and parses MHTML files.

Word outputs in this format when selecting save as a single html file.
This has been used in the wild for delivering macros, flash exploits, etc.

Extraction of mime encoded child objects should be handled by the
`mime_decoder` plugin, so is not reproduced here.
"""

from azul_runner import Feature, FeatureType, Job, State, add_settings, cmdline_run

from .mhtml import Parser
from .template import DocumentInfo


class AzulPluginMimeInfo(DocumentInfo):
    """Identifies and extracts properties from MIME HTML Documents."""

    VERSION = "2025.03.19"
    SETTINGS = add_settings(
        filter_data_types={"content": ["text/plain", "unknown", "code/xml", "document/"]},
    )

    FEATURES = [
        # Also includes inherited feature outputs from DocumentInfo class
        Feature("mime_author", desc="Author name in the MIME HTML document", type=FeatureType.String),
        Feature("mime_title", desc="Title of the document in the MIME HTML properties", type=FeatureType.String),
        Feature("mime_template", desc="Template defined in the MIME HTML properties", type=FeatureType.String),
        Feature("mime_last_author", desc="Last user to save the MIME HTML document", type=FeatureType.String),
        Feature("mime_company", desc="Company name of the author that created the document", type=FeatureType.String),
        Feature("mime_revision", desc="Revision number of the MIME document", type=FeatureType.Integer),
        Feature(
            "mime_edit_duration", desc="Total editing time spent on the document in minutes", type=FeatureType.Integer
        ),
        Feature("mime_count_pages", desc="Number of pages in the MIME HTML document", type=FeatureType.Integer),
        Feature("mime_count_words", desc="Number of words in the MIME HTML document", type=FeatureType.Integer),
        Feature(
            "mime_count_paragraphs", desc="Number of paragraphs in the MIME HTML document", type=FeatureType.Integer
        ),
        Feature("mime_count_chars", desc="Number of characters in the MIME HTML document", type=FeatureType.Integer),
        Feature("mime_count_lines", desc="Number of lines in the MIME HTML document", type=FeatureType.Integer),
        Feature(
            "mime_time_printed", desc="Time of when the MIME document was last printed", type=FeatureType.Datetime
        ),
        Feature(
            "mime_time_created", desc="Time of when the MIME document was first created", type=FeatureType.Datetime
        ),
        Feature("mime_time_saved", desc="Time of when the MIME document was last saved", type=FeatureType.Datetime),
        Feature(
            "mime_office_version",
            desc="Version of Microsoft Office that created the document",
            type=FeatureType.String,
        ),
    ]

    def execute(self, job: Job):
        """Process file data that may contain mime encoded content.

        Opt out if unable to identfy as valid content.
        """
        p = Parser(job.get_data().read())
        if not p.is_mhtml():
            return State.Label.OPT_OUT

        if p.is_mhtml_doc():
            self.add_feature_values("tag", "mhtml_doc")
            props = p.document_properties
            self.set_feature("mime_author", "Author", props)
            self.set_feature("mime_title", "Title", props)
            self.set_feature("mime_template", "Template", props)
            self.set_feature("mime_last_author", "LastAuthor", props)
            self.set_feature("mime_company", "Company", props)
            self.set_feature("mime_revision", "Revision", props)
            self.set_feature("mime_edit_duration", "TotalTime", props)
            self.set_feature("mime_time_printed", "LastPrinted", props)
            self.set_feature("mime_time_created", "Created", props)
            self.set_feature("mime_time_saved", "LastSaved", props)
            self.set_feature("mime_count_pages", "Pages", props)
            self.set_feature("mime_count_words", "Words", props)
            self.set_feature("mime_count_lines", "Lines", props)
            self.set_feature("mime_count_paragraphs", "Paragraphs", props)
            self.set_feature("mime_count_chars", "Characters", props)
            self.set_feature("mime_office_version", "Version", props)
            # shared features
            self.set_feature("document_author", "Author", props)
            self.set_feature("document_title", "Title", props)
            self.set_feature("document_company", "Company", props)
            self.set_feature("document_created", "Created", props)
            self.set_feature("document_last_author", "LastAuthor", props)
            self.set_feature("document_last_saved", "LastSaved", props)
            self.set_feature("document_page_count", "Pages", props)
            self.set_feature("document_word_count", "Words", props)

        elif p.is_mhtml_web():
            self.add_feature_values("tag", "mhtml_web")

        else:
            self.add_feature_values("tag", "mhtml")

    def set_feature(self, feature, propname, propdict):
        """Set the specified feature name from properties, if it exists."""
        if propname in propdict:
            val = propdict[propname]
            self.add_feature_values(feature, val)


def main():
    """Run the plugin via command-line."""
    cmdline_run(plugin=AzulPluginMimeInfo)


if __name__ == "__main__":
    main()
