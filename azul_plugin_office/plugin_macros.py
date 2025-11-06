"""VBA Macros plugin.

This plugin publishes features extracted from VBA macro code embedded in OLE
or Open XML documents using oletools package.
"""

import traceback
from base64 import b64decode
from binascii import unhexlify
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
from oletools.olevba import DridexUrlDecode, FileOpenError, VBA_Parser, VBA_Scanner

VBA_PATTERNS = [
    "\nEnd Sub",
    "\nEnd Function",
    "\nDim ",
    " As String",
    " As Object",
]


class AzulPluginMacros(BinaryPlugin):
    """Plugin to run olevba across documents to extract VBA macros and metadata."""

    VERSION = "2025.03.19"

    SETTINGS = add_settings(
        filter_data_types={
            "content": [
                "document/office/",
                "document/xml",  # for open document
                "document/odt/",
                "code/vbs",
            ]
        },
    )
    FEATURES = [
        Feature("macro_error", desc="Incorrect VBA formatting errors", type=FeatureType.String),
        Feature("macro_subfile", desc="Filename of the OLE subfile within OpenXML zip", type=FeatureType.Filepath),
        Feature("macro_stream_path", desc="Stream path of the VBA macro", type=FeatureType.String),
        Feature(
            "macro_filename", desc="Filename of the VBA macro as it appears in the document", type=FeatureType.Filepath
        ),
        Feature("macro_autoexec", desc="Indicates that the macro is auto-executable", type=FeatureType.String),
        Feature("macro_suspicious", desc="Suspicious keywords that may be used by malware", type=FeatureType.String),
        Feature(
            "macro_indicator_email", desc="Email address pattern found in document macro", type=FeatureType.String
        ),
        Feature("macro_indicator_ipaddress", desc="IP address pattern found in document macro", type=FeatureType.Uri),
        Feature("macro_indicator_url", desc="URL pattern found in document macro", type=FeatureType.Uri),
        Feature(
            "macro_indicator_executable", desc="Executable filename found in document macro", type=FeatureType.Filepath
        ),
        Feature("macro_hex_string", desc="Decoded hexadecimal strings", type=FeatureType.String),
        Feature("macro_base64_string", desc="Decoded base64 string", type=FeatureType.String),
        Feature("macro_dridex_string", desc="Decoded Dridex string", type=FeatureType.String),
        Feature("filename", desc="Filename of the extracted macro", type=FeatureType.Filepath),
        Feature("tag", desc="Any informational label about the sample", type=FeatureType.String),
        Feature("corrupted", desc="A corrupted file that could not be analyzed.", type=FeatureType.String),
    ]

    def execute(self, job: Job):
        """Run oletools to extract metadata from document data.

        Will opt out if unable to identfy as valid filetype.
        """
        text = []
        # despite oletools accepting a bytes str we use filename as there
        # are still bugs present which cause some samples to throw attribute
        # errors due to references to .name for arg
        with NamedTemporaryFile(delete=True) as tmp:
            tmp.write(job.get_data().read())
            tmp.flush()
            try:
                vba = VBA_Parser(tmp.name)
            except FileOpenError:
                # File isn't anything that oletools can handle
                return State.Label.OPT_OUT
            except AttributeError:
                # Typically occurs when the file is truncated
                self.add_feature_values("macro_error", "Missing root element in OLE")
                # FUTURE why is this not considered a failure?
                return
            except ValueError as e:
                # Typically occurs when the file is corrupted or malicious.
                self.add_feature_values(
                    "corrupted", f"Malformed file OLETools thinks it can handle. error is {type(e).__name__}"
                )
                return State(
                    State.Label.COMPLETED_WITH_ERRORS,
                    message=f"Corrupted file either it's malicious or there's a bug {traceback.format_exc()}",
                )

            for filename, stream_path, macro_filename, vba_code in vba.extract_macros():
                # oletools sometimes returns bytes not str
                if isinstance(vba_code, bytes):
                    vba_code = vba_code.decode("utf-8")

                # sanity check the code as any plaintext file seems to pass through
                if macro_filename == tmp.name and not any([x in vba_code for x in VBA_PATTERNS]):
                    continue

                # filename should be the the same encoding as passed in (str)
                # but we check just in case
                if isinstance(filename, bytes):
                    filename = filename.decode("utf-8")

                # if `vba.ole_file.path_encoding` is found, then the
                # stream_path will is already be converted to bytes, else it
                # is returned as unicode.
                if isinstance(stream_path, bytes):
                    stream_path = stream_path.decode("utf-8")

                # if we are processing an orphan node, the macro_filename is
                # the same type as stream_path (either bytes or str).
                # if we are processing vba projects, then the macro_filename
                # is bytes type
                if isinstance(macro_filename, bytes):
                    macro_filename = macro_filename.decode("utf-8")

                if filename != tmp.name:
                    self.add_feature_values("macro_subfile", filename)

                if stream_path:
                    self.add_feature_values("macro_stream_path", stream_path)

                if macro_filename != tmp.name:
                    # add stream path for filepath
                    macro_filename = "%s/%s" % (stream_path, macro_filename)
                    self.add_feature_values("macro_filename", macro_filename)
                else:
                    # input file is the macro
                    self.add_feature_values("tag", "vba_macro")
                    macro_filename = ""

                # raise extracted macros as children
                if macro_filename and not self.default_sheet(vba_code):
                    meta = {
                        "tag": "vba_macro",
                        "filename": macro_filename,
                    }
                    c = self.add_child_with_data({"action": "extracted"}, vba_code.encode("utf-8"))
                    c.add_many_feature_values(meta)
                    # Append the macro code to the output text
                    text.append("'\n' %s:\n'\n%s\n" % (macro_filename, vba_code))

                # find suspicious strings/indicators in the code
                for name, value in self.analyse(vba_code):
                    self.add_feature_values(name, FeatureValue(value, label=macro_filename))

        vba.close()
        # Save the extracted macros as text for search and display
        if text:
            text = "\n".join(text)
            self.add_text(text, "vba")

    def default_sheet(self, vba_code):
        """Return True if the code appears to be a default excel worksheet vba block."""
        for x in vba_code.splitlines():
            if x.strip() and not x.startswith("Attribute"):
                return False
        return True

    def analyse(self, vba_code):
        """Scan the VBA code for anything suspicious and yield it as a feature.

        :return: generator of tuples: feature name, value
        """
        parser = VBA_Scanner(vba_code)
        for label, keyword, desc in parser.scan():
            desc = desc.replace(" (use option --deobf to deobfuscate)", "")
            if label == "AutoExec":
                yield "macro_autoexec", "%s - %s" % (keyword, desc)

            elif label == "Suspicious":
                if keyword not in ("Hex Strings", "Base64 Strings", "Dridex Strings"):
                    msg = "%s - %s" % (keyword, desc)
                    yield "macro_suspicious", msg

            elif label == "IOC":
                if desc.startswith("URL"):
                    yield "macro_indicator_url", keyword
                elif desc.startswith("IPv4 address"):
                    yield "macro_indicator_ipaddress", keyword
                elif desc.startswith("Executable file name"):
                    yield "macro_indicator_executable", keyword
                elif desc.startswith("E-mail address"):
                    yield "macro_indicator_email", keyword

            elif label == "Hex String":
                # any size constraints with these?
                yield "macro_hex_string", unhexlify(desc).decode("utf-8")

            elif label == "Base64 String":
                yield "macro_base64_string", b64decode(desc).decode("utf-8")

            elif label == "Dridex string":
                yield "macro_dridex_string", DridexUrlDecode(desc).decode("utf-8")


def main():
    """Run plugin via command-line."""
    cmdline_run(plugin=AzulPluginMacros)


if __name__ == "__main__":
    main()
