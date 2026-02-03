"""RTF Meta Info Plugin.

This plugin publishes features extracted from rtf documents.
"""

import re
from datetime import datetime

from azul_runner import Feature, FeatureType, Job, State, add_settings, cmdline_run

from . import rtfinfo
from .template import DocumentInfo


class AzulPluginRtfInfo(DocumentInfo):
    """Runs rtfinfo parser across document to extract/feature properties."""

    VERSION = "2025.03.19"
    SETTINGS = add_settings(
        filter_data_types={"content": ["document/office/rtf"]},
    )

    FEATURES = [
        # Also includes inherited feature outputs from DocumentInfo class
        Feature("rtf_type", desc="rtf type indicated by the first few bytes of the file", type=bytes),
        Feature("rtf_title", desc="Title of the document", type=FeatureType.String),
        Feature("rtf_subject", desc="Subject of the document", type=FeatureType.String),
        Feature("rtf_author", desc="Author of the document", type=FeatureType.String),
        Feature("rtf_manager", desc="Manager of the author", type=FeatureType.String),
        Feature("rtf_company", desc="Company of the author", type=FeatureType.String),
        Feature("rtf_operator", desc="Last user to edit the document", type=FeatureType.String),
        Feature("rtf_category", desc="Category of the document", type=FeatureType.String),
        Feature("rtf_keywords", desc="Selected keywords for the document", type=FeatureType.String),
        Feature("rtf_comment", desc="Comments saved with the document", type=FeatureType.String),
        Feature("rtf_version", desc="Version number of the document", type=FeatureType.Integer),
        Feature("rtf_doccomm", desc="Comments displayed in the Summary Info", type=FeatureType.String),
        Feature("rtf_linkbase", desc="Base address for all relative link paths", type=FeatureType.String),
        # user defined properties mappings?
        Feature("rtf_linkval", desc="Bookmark name that contains text for prop value", type=FeatureType.String),
        Feature("rtf_vern", desc="Internal version number", type=FeatureType.Integer),
        Feature("rtf_creatim", desc="Document creation time", type=FeatureType.Datetime),
        Feature("rtf_revtim", desc="Last revision time of the document", type=FeatureType.Datetime),
        Feature("rtf_printim", desc="Last print time of the document", type=FeatureType.Datetime),
        Feature("rtf_buptim", desc="Last backup time of the document", type=FeatureType.Datetime),
        Feature("rtf_edmins", desc="Time spent editing document, in minutes", type=FeatureType.Integer),
        Feature("rtf_nofpages", desc="Number of pages", type=FeatureType.Integer),
        Feature("rtf_nofwords", desc="Number of words", type=FeatureType.Integer),
        Feature("rtf_nofchars", desc="Number of characters not including spaces", type=FeatureType.Integer),
        Feature("rtf_nofcharsws", desc="Number of chars including spaces", type=FeatureType.Integer),
        Feature("rtf_id", desc="Internal ID number", type=FeatureType.Integer),
        Feature(
            "rtf_invalid_type_count", "Count of malformed/mismatching control word types", type=FeatureType.Integer
        ),
    ]

    # mapping to authored, common document feature names
    AUTHORED_MAP = {
        "rtf_author": "document_author",
        "rtf_operator": "document_last_author",
        "rtf_title": "document_title",
        "rtf_company": "document_company",
        "rtf_nofpages": "document_page_count",
        "rtf_nofwords": "document_word_count",
        "rtf_creatim": "document_created",
        "rtf_revtim": "document_last_saved",
    }

    def execute(self, job: Job):
        """Extract features from supplied rtf data."""
        data = job.get_data()
        features = {}
        buf = data.read(2048)
        # check rtf magic. Allow whitespace between {\ and rt
        rtf_magic_regex = rb"{\\\s*rt"
        if not re.match(rtf_magic_regex, buf):
            return State.Label.OPT_OUT

        buf += data.read()
        # extract the rtftype - between first \ and next \ or {
        rtftype_regex = rb"\\[a-zA-Z0-9\r\n\s]{2,}[\\{]"
        rtftype_search = re.search(rtftype_regex, buf)
        if rtftype_search is None:
            return State.Label.OPT_OUT

        rtftype = rtftype_search.group(0)
        rtftype = rtftype[1 : len(rtftype) - 1]
        features["rtf_type"] = rtftype

        # run rtfinfo
        try:
            parser = rtfinfo.RtfParser(buf)

        # capture parser errors as a feature
        except rtfinfo.RtfParserError:
            self.is_malformed("RTF file could not be parsed.")
            return

        # keep track of any malformed control word types
        bad_types = 0

        # set azul features
        for control_word, values in parser.info_group.items():
            feature_name = "rtf_" + control_word.lower()
            if not isinstance(values, list):
                values = [values]

            for i, v in enumerate(values):
                if not self._is_expected_feature_type(feature_name, v):
                    bad_types += 1
                    values[i] = None
                # remove defaulted dates (by parser)
                elif type(v) is datetime and v == datetime(1, 1, 1, 0, 0, 0):
                    values[i] = None
                # map field byte values to str
                elif type(v) is bytes:
                    if v:
                        try:
                            values[i] = v.decode("utf-8")
                        except UnicodeDecodeError:
                            # Some files appear to use symbols in 8-bit space (not UTF-8/16)
                            # - handle these:
                            values[i] = v.decode("iso-8859-1")
                    else:
                        values[i] = None

            # filter out bad values
            values = [x for x in values if x is not None]
            features[feature_name] = values
            # map to generic equivalents
            if feature_name in self.AUTHORED_MAP:
                features[self.AUTHORED_MAP[feature_name]] = values

        if bad_types:
            features["rtf_invalid_type_count"] = bad_types

        self.add_many_feature_values(features)

    def _is_expected_feature_type(self, feature_name, value):
        """Ensure the value is of expected type."""
        feature: Feature = None
        for f in self.FEATURES:
            if f.name == feature_name:
                feature = f
                break
        if not feature:
            return False
        # we decode strings from the parser
        if feature.typeref is str:
            return isinstance(value, bytes)
        return isinstance(value, feature.typeref)


def main():
    """Run plugin via command-line."""
    cmdline_run(plugin=AzulPluginRtfInfo)


if __name__ == "__main__":
    main()
