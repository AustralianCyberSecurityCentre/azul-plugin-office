"""Document Info Template.

Defines common features shared by multiple document info extraction plugins.
"""

from azul_runner import BinaryPlugin, Feature, FeatureType


class DocumentInfo(BinaryPlugin):
    """Common feature definitions."""

    FEATURES = [
        Feature(name="document_title", desc="Document title", type=FeatureType.String),
        Feature(name="document_author", desc="Document author name", type=FeatureType.String),
        Feature(name="document_last_author", desc="Name of user who last saved the document", type=FeatureType.String),
        Feature(
            name="document_company", desc="Company name of user who authored the document", type=FeatureType.String
        ),
        Feature(name="document_created", desc="Time the document was created", type=FeatureType.Datetime),
        Feature(name="document_last_saved", desc="Time the document was last saved", type=FeatureType.Datetime),
        Feature(name="document_word_count", desc="Count of words in the document", type=FeatureType.Integer),
        Feature(name="document_page_count", desc="Count of pages in the document", type=FeatureType.Integer),
        Feature(name="tag", desc="An informational label about the document", type=FeatureType.String),
    ]
