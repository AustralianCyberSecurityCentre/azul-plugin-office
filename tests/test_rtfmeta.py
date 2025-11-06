"""rtfinfo test suite - Test the rtfinfo plugin"""

import datetime

from azul_runner import FV, Event, JobResult, State, test_template

from azul_plugin_office.plugin_rtfmeta import AzulPluginRtfInfo


class TestExecute(test_template.TestPlugin):
    PLUGIN_TO_TEST = AzulPluginRtfInfo

    def test_on_benign_rtf_document(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "15c8614f493cf081b53ea379b06d759fc51cf94d61d245baab5efb77648bf8d4", "Benign RTF."
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
                        entity_id="15c8614f493cf081b53ea379b06d759fc51cf94d61d245baab5efb77648bf8d4",
                        features={
                            "document_author": [FV("B, A")],
                            "document_created": [FV(datetime.datetime(2013, 9, 12, 14, 53))],
                            "document_last_author": [FV("B, A")],
                            "document_last_saved": [FV(datetime.datetime(2013, 9, 12, 14, 54))],
                            "document_page_count": [FV(1)],
                            "document_word_count": [FV(7)],
                            "rtf_author": [FV("B, A")],
                            "rtf_creatim": [FV(datetime.datetime(2013, 9, 12, 14, 53))],
                            "rtf_edmins": [FV(1)],
                            "rtf_nofchars": [FV(43)],
                            "rtf_nofcharsws": [FV(49)],
                            "rtf_nofpages": [FV(1)],
                            "rtf_nofwords": [FV(7)],
                            "rtf_operator": [FV("B, A")],
                            "rtf_revtim": [FV(datetime.datetime(2013, 9, 12, 14, 54))],
                            "rtf_type": [FV(b"rtf1")],
                            "rtf_vern": [FV(49255)],
                            "rtf_version": [FV(1)],
                        },
                    )
                ],
            ),
        )

    def test_on_benign_rtf_document_different_magic(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "83c838abd0c98bc5abb54dbab58056cd6ab9a387cd269c15320dd7fc6ce25102",
                        "Benign RTF with different magic then expected.",
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
                        entity_id="83c838abd0c98bc5abb54dbab58056cd6ab9a387cd269c15320dd7fc6ce25102",
                        features={
                            "document_author": [FV("B, A")],
                            "document_created": [FV(datetime.datetime(2013, 9, 12, 14, 53))],
                            "document_last_author": [FV("B, A")],
                            "document_last_saved": [FV(datetime.datetime(2013, 9, 12, 14, 54))],
                            "document_page_count": [FV(1)],
                            "document_word_count": [FV(7)],
                            "rtf_author": [FV("B, A")],
                            "rtf_creatim": [FV(datetime.datetime(2013, 9, 12, 14, 53))],
                            "rtf_edmins": [FV(1)],
                            "rtf_nofchars": [FV(43)],
                            "rtf_nofcharsws": [FV(49)],
                            "rtf_nofpages": [FV(1)],
                            "rtf_nofwords": [FV(7)],
                            "rtf_operator": [FV("B, A")],
                            "rtf_revtim": [FV(datetime.datetime(2013, 9, 12, 14, 54))],
                            "rtf_type": [FV(b"      rtx")],
                            "rtf_vern": [FV(49255)],
                            "rtf_version": [FV(1)],
                        },
                    )
                ],
            ),
        )

    def test_on_malicious_rtf_document(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "60fd85657464c1388dd26cd336982f2e242959c828a696672ef9b1945dee62df",
                        "Malicious RTF, cve-2010-3333.",
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
                        entity_id="60fd85657464c1388dd26cd336982f2e242959c828a696672ef9b1945dee62df",
                        features={"rtf_type": [FV(b"rtf1")]},
                    )
                ],
            ),
        )

    def test_on_malicious_fuzzed_rtf(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "e378eef9f4ea1511aa5e368cb0e52a8a68995000b8b1e6207717d9ed09e8555a",
                        "Malicious RTF with invalid control word types, cve-2012-0158.",
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
                        entity_id="e378eef9f4ea1511aa5e368cb0e52a8a68995000b8b1e6207717d9ed09e8555a",
                        features={
                            "document_author": [
                                FV("f1"),
                                FV("ismail - [20"),
                                FV("ismail - [2010]"),
                                FV("ismail - [2010info"),
                                FV("ismail - [201o3"),
                            ],
                            "document_created": [FV(datetime.datetime(2014, 3, 8, 3, 9))],
                            "document_last_author": [FV("ismail - [2010]")],
                            "document_last_saved": [
                                FV(datetime.datetime(2014, 3, 8, 0, 0)),
                                FV(datetime.datetime(2014, 3, 8, 3, 9)),
                            ],
                            "rtf_author": [
                                FV("f1"),
                                FV("ismail - [20"),
                                FV("ismail - [2010]"),
                                FV("ismail - [2010info"),
                                FV("ismail - [201o3"),
                            ],
                            "rtf_creatim": [FV(datetime.datetime(2014, 3, 8, 3, 9))],
                            "rtf_invalid_type_count": [FV(18)],
                            "rtf_nofcharsws": [FV(69)],
                            "rtf_operator": [FV("ismail - [2010]")],
                            "rtf_revtim": [
                                FV(datetime.datetime(2014, 3, 8, 0, 0)),
                                FV(datetime.datetime(2014, 3, 8, 3, 9)),
                            ],
                            "rtf_type": [FV(b"rt")],
                        },
                    )
                ],
            ),
        )

    def test_on_rtf_document_no_features(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "08001c39678ca1fa3aac89100f8e6af41f925ee3386cd208f72d21a8235b9150",
                        "Benign RTF with no metadata.",
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
                        entity_id="08001c39678ca1fa3aac89100f8e6af41f925ee3386cd208f72d21a8235b9150",
                        features={"rtf_type": [FV(b"rtf1")]},
                    )
                ],
            ),
        )

    def test_on_non_ascii_binary(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "66381cbdce66dbae875764b83b66172e457d7f5a0f23e87282dd0c4dd7890f82", "Benign RTF."
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
                        entity_id="66381cbdce66dbae875764b83b66172e457d7f5a0f23e87282dd0c4dd7890f82",
                        features={
                            "document_author": [
                                FV("RWaters"),
                            ],
                            "document_created": [FV(datetime.datetime(2005, 3, 24, 12, 7))],
                            "document_last_author": [FV("ilko")],
                            "document_last_saved": [
                                FV(datetime.datetime(2005, 3, 31, 11, 23)),
                            ],
                            "document_page_count": [FV(1)],
                            "document_title": [FV("Copyright \u00a9 2015 Speed Guide, Inc")],
                            "document_word_count": [FV((392))],
                            "rtf_author": [
                                FV("RWaters"),
                            ],
                            "rtf_creatim": [FV(datetime.datetime(2005, 3, 24, 12, 7))],
                            "rtf_edmins": [FV(12)],
                            "rtf_nofchars": [FV(2237)],
                            "rtf_nofcharsws": [FV(0)],
                            "rtf_nofpages": [FV(1)],
                            "rtf_nofwords": [FV(392)],
                            "rtf_operator": [FV("ilko")],
                            "rtf_revtim": [FV(datetime.datetime(2005, 3, 31, 11, 23))],
                            "rtf_title": [FV("Copyright \u00a9 2015 Speed Guide, Inc")],
                            "rtf_type": [FV(b"rtf1")],
                            "rtf_vern": [FV(8247)],
                            "rtf_version": [FV(4)],
                        },
                    )
                ],
            ),
        )

    def test_bad_rtf_file_fails_to_be_parsed(self):
        """Test that fails to parse a bad rtf file."""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "12047ca7ecfe6caf4a9798565ade481d1a1c46f7d1aa09b6576b11a36b431547",
                        "Malicious RTF, cve-2017-1182.",
                    ),
                )
            ],
            verify_input_content=False,
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="12047ca7ecfe6caf4a9798565ade481d1a1c46f7d1aa09b6576b11a36b431547",
                        features={"malformed": [FV("RTF file could not be parsed.")]},
                    )
                ],
            ),
        )
