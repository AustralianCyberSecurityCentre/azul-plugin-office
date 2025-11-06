"""VBA Macros test suite."""

from azul_runner import (
    FV,
    Event,
    EventData,
    EventParent,
    JobResult,
    State,
    test_template,
)

from azul_plugin_office.plugin_macros import AzulPluginMacros


class TestExecute(test_template.TestPlugin):
    """Test suite for azul-macros plugin."""

    PLUGIN_TO_TEST = AzulPluginMacros

    def test_malicious_doc(self):
        """Malicious doc not containing any macros."""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "b5a51fa855a995e3ec39bd2893e8109cbc8578d313d907339420d4a56745ec6a",
                        "Malicious Microsoft Word document, malware family mdrop.",
                    ),
                )
            ]
        )
        self.assertJobResult(result, JobResult(state=State(State.Label.COMPLETED_EMPTY)))

    def test_partial_doc(self):
        """Malicious Power Point."""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "a3d6d98567725d271580e3264ce32e5f5298d9de52cbd5a0d69771087aa4e1a4",
                        "Malicious Power Point.",
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
                        entity_id="a3d6d98567725d271580e3264ce32e5f5298d9de52cbd5a0d69771087aa4e1a4",
                        features={"macro_error": [FV("Missing root element in OLE")]},
                    )
                ],
            ),
        )

    def test_benign_autoopen_macro(self):
        """MS Word 2003 Document with a benign AutoOpen macro."""
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
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="ffc7df1b29a93d861ad70ed3d5bccdfa4312140185520cc6a58cce5b9e11215a",
                        data=[
                            EventData(
                                hash="8af5a20ed96e75cc8f6c05d961eb358e9fec494466fa49a66ad2c0f6fa2e6852",
                                label="text",
                                language="vba",
                            )
                        ],
                        features={
                            "macro_autoexec": [
                                FV(
                                    "AutoOpen - Runs when the Word document is opened",
                                    label="Macros/VBA/NewMacros/NewMacros.bas",
                                )
                            ],
                            "macro_filename": [
                                FV("Macros/VBA/NewMacros/NewMacros.bas"),
                                FV("Macros/VBA/ThisDocument/ThisDocument.cls"),
                            ],
                            "macro_stream_path": [FV("Macros/VBA/NewMacros"), FV("Macros/VBA/ThisDocument")],
                        },
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="ffc7df1b29a93d861ad70ed3d5bccdfa4312140185520cc6a58cce5b9e11215a",
                        ),
                        entity_type="binary",
                        entity_id="3bdf054e9c8a1dee631e90f0c036d70292dfec809022720273b05fc2bb09e4a8",
                        relationship={"action": "extracted"},
                        data=[
                            EventData(
                                hash="3bdf054e9c8a1dee631e90f0c036d70292dfec809022720273b05fc2bb09e4a8",
                                label="content",
                            )
                        ],
                        features={
                            "filename": [FV("Macros/VBA/NewMacros/NewMacros.bas")],
                            "tag": [FV("vba_macro")],
                        },
                    ),
                ],
                data={
                    "3bdf054e9c8a1dee631e90f0c036d70292dfec809022720273b05fc2bb09e4a8": b"",
                    "8af5a20ed96e75cc8f6c05d961eb358e9fec494466fa49a66ad2c0f6fa2e6852": b"",
                },
            ),
        )

    def test_spreadsheet_macro(self):
        """
        MS Excel 2003 spreadshet with a "malicious" macro.

        Sourced from:
            http://digital-forensics.sans.org/blog/2009/11/23/extracting-vb-macros-from-malicious-documents
        """
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "dcf4e954c0880ef6bf3ad7da82f93fba02f5b342bcc53e436c8686bba1e47e7d",
                        "Malicious Microsoft Excel document with macros.",
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
                        entity_id="dcf4e954c0880ef6bf3ad7da82f93fba02f5b342bcc53e436c8686bba1e47e7d",
                        data=[
                            EventData(
                                hash="36287900875ba581ac73a0f85342ac86dea30f08496b2e7922d1e2cd5176b445",
                                label="text",
                                language="vba",
                            )
                        ],
                        features={
                            "macro_autoexec": [
                                FV(
                                    "Workbook_Open - Runs when the Excel Workbook is opened",
                                    label="_VBA_PROJECT_CUR/VBA/ThisWorkbook/ThisWorkbook.cls",
                                )
                            ],
                            "macro_filename": [
                                FV("_VBA_PROJECT_CUR/VBA/Sheet1/Sheet1.cls"),
                                FV("_VBA_PROJECT_CUR/VBA/Sheet2/Sheet2.cls"),
                                FV("_VBA_PROJECT_CUR/VBA/Sheet3/Sheet3.cls"),
                                FV("_VBA_PROJECT_CUR/VBA/ThisWorkbook/ThisWorkbook.cls"),
                            ],
                            "macro_indicator_executable": [
                                FV("notepad.exe", label="_VBA_PROJECT_CUR/VBA/ThisWorkbook/ThisWorkbook.cls")
                            ],
                            "macro_indicator_ipaddress": [
                                FV("127.0.0.1", label="_VBA_PROJECT_CUR/VBA/ThisWorkbook/ThisWorkbook.cls")
                            ],
                            "macro_stream_path": [
                                FV("_VBA_PROJECT_CUR/VBA/Sheet1"),
                                FV("_VBA_PROJECT_CUR/VBA/Sheet2"),
                                FV("_VBA_PROJECT_CUR/VBA/Sheet3"),
                                FV("_VBA_PROJECT_CUR/VBA/ThisWorkbook"),
                            ],
                            "macro_suspicious": [
                                FV(
                                    "CreateObject - May create an OLE object",
                                    label="_VBA_PROJECT_CUR/VBA/ThisWorkbook/ThisWorkbook.cls",
                                ),
                                FV(
                                    "Run - May run an executable file or a system command",
                                    label="_VBA_PROJECT_CUR/VBA/ThisWorkbook/ThisWorkbook.cls",
                                ),
                                FV(
                                    "Shell - May run an executable file or a system command",
                                    label="_VBA_PROJECT_CUR/VBA/ThisWorkbook/ThisWorkbook.cls",
                                ),
                                FV(
                                    "WScript.Shell - May run an executable file or a system command",
                                    label="_VBA_PROJECT_CUR/VBA/ThisWorkbook/ThisWorkbook.cls",
                                ),
                                FV(
                                    "command - May run PowerShell commands",
                                    label="_VBA_PROJECT_CUR/VBA/ThisWorkbook/ThisWorkbook.cls",
                                ),
                            ],
                        },
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="dcf4e954c0880ef6bf3ad7da82f93fba02f5b342bcc53e436c8686bba1e47e7d",
                        ),
                        entity_type="binary",
                        entity_id="df630eed2dc0ff27e77e4f8a54c5091845362a5920991648ba0cc1b043721ce0",
                        relationship={"action": "extracted"},
                        data=[
                            EventData(
                                hash="df630eed2dc0ff27e77e4f8a54c5091845362a5920991648ba0cc1b043721ce0",
                                label="content",
                            )
                        ],
                        features={
                            "filename": [FV("_VBA_PROJECT_CUR/VBA/ThisWorkbook/ThisWorkbook.cls")],
                            "tag": [FV("vba_macro")],
                        },
                    ),
                ],
                data={
                    "df630eed2dc0ff27e77e4f8a54c5091845362a5920991648ba0cc1b043721ce0": b"",
                    "36287900875ba581ac73a0f85342ac86dea30f08496b2e7922d1e2cd5176b445": b"",
                },
            ),
        )

    def test_ooxml_macro(self):
        """Office Open XML document from VirusTotal with embedded macros."""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "6e979eaf8a5b76ff14ec2784a5eac0ff509730bfebb351af37b8c9b6a6cc20e2",
                        "Benign Microsoft Open XML document.",
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
                        entity_id="6e979eaf8a5b76ff14ec2784a5eac0ff509730bfebb351af37b8c9b6a6cc20e2",
                        data=[
                            EventData(
                                hash="508e9eb3e5d7b60e759975ae210a3650a69fc4bf09fae969d401b2f5b8f4c34d",
                                label="text",
                                language="vba",
                            )
                        ],
                        features={
                            "macro_autoexec": [
                                FV(
                                    "AutoClose - Runs when the Word document is closed",
                                    label="VBA/NewMacros/NewMacros.bas",
                                ),
                                FV(
                                    "AutoOpen - Runs when the Word document is opened",
                                    label="VBA/NewMacros/NewMacros.bas",
                                ),
                                FV(
                                    "Document_Open - Runs when the Word or Publisher document is opened",
                                    label="VBA/ThisDocument/ThisDocument.cls",
                                ),
                                FV(
                                    "update_Click - Runs when the file is opened and ActiveX objects trigger events",
                                    label="VBA/ThisDocument/ThisDocument.cls",
                                ),
                            ],
                            "macro_filename": [
                                FV("VBA/Lamtronso/Lamtronso.bas"),
                                FV("VBA/NewMacros/NewMacros.bas"),
                                FV("VBA/ThisDocument/ThisDocument.cls"),
                                FV("VBA/Wordsochu/Wordsochu.bas"),
                            ],
                            "macro_stream_path": [
                                FV("VBA/Lamtronso"),
                                FV("VBA/NewMacros"),
                                FV("VBA/ThisDocument"),
                                FV("VBA/Wordsochu"),
                            ],
                            "macro_subfile": [FV("word/vbaProject.bin")],
                            "macro_suspicious": [
                                FV(
                                    ".Variables - May use Word Document Variables to store and hide data",
                                    label="VBA/NewMacros/NewMacros.bas",
                                ),
                                FV(
                                    "Call - May call a DLL using Excel 4 Macros (XLM/XLF)",
                                    label="VBA/NewMacros/NewMacros.bas",
                                ),
                                FV(
                                    "Call - May call a DLL using Excel 4 Macros (XLM/XLF)",
                                    label="VBA/ThisDocument/ThisDocument.cls",
                                ),
                                FV(
                                    "Call - May call a DLL using Excel 4 Macros (XLM/XLF)",
                                    label="VBA/Wordsochu/Wordsochu.bas",
                                ),
                                FV(
                                    "Chr - May attempt to obfuscate specific strings",
                                    label="VBA/Wordsochu/Wordsochu.bas",
                                ),
                                FV(
                                    "ChrW - May attempt to obfuscate specific strings",
                                    label="VBA/Wordsochu/Wordsochu.bas",
                                ),
                            ],
                        },
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="6e979eaf8a5b76ff14ec2784a5eac0ff509730bfebb351af37b8c9b6a6cc20e2",
                        ),
                        entity_type="binary",
                        entity_id="9933ed65314a201cd936a40d5fb3cd9e72e84faed33890903a35de05fcda127a",
                        relationship={"action": "extracted"},
                        data=[
                            EventData(
                                hash="9933ed65314a201cd936a40d5fb3cd9e72e84faed33890903a35de05fcda127a",
                                label="content",
                            )
                        ],
                        features={
                            "filename": [FV("VBA/ThisDocument/ThisDocument.cls")],
                            "tag": [FV("vba_macro")],
                        },
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="6e979eaf8a5b76ff14ec2784a5eac0ff509730bfebb351af37b8c9b6a6cc20e2",
                        ),
                        entity_type="binary",
                        entity_id="cce1306631abce74eee7024c9a5e5f2b4e942d5152529f7a4fc3faf6d1ab0a52",
                        relationship={"action": "extracted"},
                        data=[
                            EventData(
                                hash="cce1306631abce74eee7024c9a5e5f2b4e942d5152529f7a4fc3faf6d1ab0a52",
                                label="content",
                            )
                        ],
                        features={"filename": [FV("VBA/NewMacros/NewMacros.bas")], "tag": [FV("vba_macro")]},
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="6e979eaf8a5b76ff14ec2784a5eac0ff509730bfebb351af37b8c9b6a6cc20e2",
                        ),
                        entity_type="binary",
                        entity_id="a817b0c67c3e84a37e3bb327a0f40d1988688ef43e0ece9e24ab348b2fdea90e",
                        relationship={"action": "extracted"},
                        data=[
                            EventData(
                                hash="a817b0c67c3e84a37e3bb327a0f40d1988688ef43e0ece9e24ab348b2fdea90e",
                                label="content",
                            )
                        ],
                        features={"filename": [FV("VBA/Wordsochu/Wordsochu.bas")], "tag": [FV("vba_macro")]},
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="6e979eaf8a5b76ff14ec2784a5eac0ff509730bfebb351af37b8c9b6a6cc20e2",
                        ),
                        entity_type="binary",
                        entity_id="2c5796d37889898883f4a949c59b24f0e5a5c5541d9e7062c54d02e4110acae3",
                        relationship={"action": "extracted"},
                        data=[
                            EventData(
                                hash="2c5796d37889898883f4a949c59b24f0e5a5c5541d9e7062c54d02e4110acae3",
                                label="content",
                            )
                        ],
                        features={"filename": [FV("VBA/Lamtronso/Lamtronso.bas")], "tag": [FV("vba_macro")]},
                    ),
                ],
                data={
                    "9933ed65314a201cd936a40d5fb3cd9e72e84faed33890903a35de05fcda127a": b"",
                    "cce1306631abce74eee7024c9a5e5f2b4e942d5152529f7a4fc3faf6d1ab0a52": b"",
                    "a817b0c67c3e84a37e3bb327a0f40d1988688ef43e0ece9e24ab348b2fdea90e": b"",
                    "2c5796d37889898883f4a949c59b24f0e5a5c5541d9e7062c54d02e4110acae3": b"",
                    "508e9eb3e5d7b60e759975ae210a3650a69fc4bf09fae969d401b2f5b8f4c34d": b"",
                },
            ),
        )

    def test_negative_seek(self):
        """Malicious doc not containing any macros."""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "58a2edd6395a65d47fee3a095ec41c92a322e0b123a0e1c8b8314759b1f8ffe6",
                        "Corrupted Microsoft Excel Document.",
                    ),
                )
            ]
        )
        result.state.message = ""
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED_WITH_ERRORS, message=""),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="58a2edd6395a65d47fee3a095ec41c92a322e0b123a0e1c8b8314759b1f8ffe6",
                        features={
                            "corrupted": [FV("Malformed file OLETools thinks it can handle. error is ValueError")]
                        },
                    )
                ],
            ),
        )
