"""Office DDE Info plugin.

This plugin looks for embedded DDE links in Microsoft Office files.
These links can be used to provide an execution vector for malware.
"""

import re
from tempfile import NamedTemporaryFile

from azul_runner import (
    BinaryPlugin,
    Feature,
    FeatureType,
    FeatureValue,
    Job,
    State,
    add_settings,
    cmdline_run,
)
from oletools import msodde

URL_PAT = re.compile(r'(https?://[^\'"\)\(\r\n\\]+)')


class AzulPluginOfficeDDE(BinaryPlugin):
    """Runs oletools msodde to extract any DDE links from documents."""

    VERSION = "2025.03.19"

    SETTINGS = add_settings(
        filter_data_types={
            "content": [
                "document/office/word",
                "document/office/excel",
                "document/office/powerpoint",
                "document/office/visio",
                "document/office/unknown",
                "document/xml",  # for open documents
                "document/odt/",
                "unknown",
            ]
        }
    )
    FEATURES = [
        Feature("dde_command", desc="Embedded Office DDE command to execute", type=FeatureType.String),
        Feature("dde_url", desc="URL Extracted from an embedded DDE link", type=FeatureType.Uri),
    ]

    def execute(self, job: Job):
        """Run oletools to extract DDE metadata from document data.

        Will opt out if unable to identfy as valid filetype.
        """
        features = {}
        with NamedTemporaryFile(delete=True) as tmp:
            tmp.write(job.get_data().read())
            tmp.flush()
            try:
                dde = msodde.process_file(tmp.name)
            except Exception:
                # File isn't anything that oletools can handle
                return State(State.Label.OPT_OUT)

            if dde:
                features["dde_command"] = FeatureValue(dde.strip())
                for m in re.finditer(URL_PAT, dde):
                    features.setdefault("dde_url", []).append(m.group(1))
        self.add_many_feature_values(features)


def main():
    """Run plugin via command-line."""
    cmdline_run(plugin=AzulPluginOfficeDDE)


if __name__ == "__main__":
    main()
