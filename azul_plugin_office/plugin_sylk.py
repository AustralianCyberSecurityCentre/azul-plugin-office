"""Office SYmbolic LinK Plugin.

This plugin looks for Excel .slk text files and parses their content
for suspicious commands.
"""

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

from .mssylk import Sylk


class AzulPluginOfficeSylk(BinaryPlugin):
    """Parse Text content to identify and Extract features for Excel .slk files."""

    VERSION = "2025.03.19"
    SETTINGS = add_settings(filter_data_types={"content": ["document/office/sylk"]})
    FEATURES = [
        Feature("sylk_function", desc="Macro function found in symbolic link file", type=FeatureType.String),
        Feature(
            "sylk_command", desc="Embedded execution command in Office symbolic link file", type=FeatureType.String
        ),
        Feature(
            "sylk_command_normalised",
            desc="Normalised version of extracted execution commands",
            type=FeatureType.String,
        ),
        Feature("sylk_url", desc="URL extracted from an embedded symbolic link command", type=FeatureType.Uri),
        # should file type be overridden here or do we need to diverge from vt file types in main processing
        Feature("file_format_legacy", desc="System normalised file type format", type=FeatureType.String),
    ]

    def execute(self, job: Job):
        """Identify and parse .slk files.

        Will opt out if unable to identfy as valid filetype.
        """
        data = job.get_data()
        slk = Sylk(data)
        if not slk.is_sylk:
            # not valid looking .slk
            return State.Label.OPT_OUT

        features = {
            "file_format_legacy": "SYLK",
            "sylk_function": slk.functions,
            "sylk_url": slk.urls,
            "sylk_command_normalised": slk.normalised,
        }
        for c in slk.commands:
            features.setdefault("sylk_command", []).append(FeatureValue(c["param"], label=c["function"]))

        self.add_many_feature_values(features)


def main():
    """Run plugin via command-line."""
    cmdline_run(plugin=AzulPluginOfficeSylk)


if __name__ == "__main__":
    main()
