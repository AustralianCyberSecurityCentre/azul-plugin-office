"""MIME Document Info test suite - Test plugin features"""

import datetime

from azul_runner import FV, Event, JobResult, State, test_template

from azul_plugin_office.plugin_mimeinfo import AzulPluginMimeInfo


class TestExecute(test_template.TestPlugin):
    PLUGIN_TO_TEST = AzulPluginMimeInfo

    def test_mime_doc(self):
        """Test parsing document properties from MIME HTML doc"""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "0dc315e0b3d9f4098ea5cac977b9814e3c6e9116cf296c1bbfcb3ab95c72ca99",
                        "Malicious HTML document, cve-2012-0158.",
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
                        entity_id="0dc315e0b3d9f4098ea5cac977b9814e3c6e9116cf296c1bbfcb3ab95c72ca99",
                        features={
                            "document_author": [FV("User323")],
                            "document_created": [FV(datetime.datetime(2012, 5, 1, 14, 8))],
                            "document_last_author": [FV("User426")],
                            "document_last_saved": [FV(datetime.datetime(2012, 5, 1, 14, 12))],
                            "document_page_count": [FV(44)],
                            "document_title": [FV(" ")],
                            "document_word_count": [FV(17)],
                            "mime_author": [FV("User323")],
                            "mime_count_chars": [FV(101)],
                            "mime_count_lines": [FV(1)],
                            "mime_count_pages": [FV(44)],
                            "mime_count_paragraphs": [FV(1)],
                            "mime_count_words": [FV(17)],
                            "mime_edit_duration": [FV(2)],
                            "mime_last_author": [FV("User426")],
                            "mime_office_version": [FV("11.9999")],
                            "mime_revision": [FV(4)],
                            "mime_time_created": [FV(datetime.datetime(2012, 5, 1, 14, 8))],
                            "mime_time_saved": [FV(datetime.datetime(2012, 5, 1, 14, 12))],
                            "mime_title": [FV(" ")],
                            "tag": [FV("mhtml_doc")],
                        },
                    )
                ],
            ),
        )

    def test_mime_webarchive(self):
        """Test identifying a saved single page webarchive in MIME format"""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "8ad5920ebdb440e5fd72fc07f79896266f5b9d7c0638a5602676dad05c5f43ea", "Web archive."
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
                        entity_id="8ad5920ebdb440e5fd72fc07f79896266f5b9d7c0638a5602676dad05c5f43ea",
                        features={"tag": [FV("mhtml_web")]},
                    )
                ],
            ),
        )
