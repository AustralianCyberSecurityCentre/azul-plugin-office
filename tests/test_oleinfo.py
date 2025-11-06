"""OLE Info test suite - Test plugin features"""

import datetime

from azul_runner import FV, Event, JobResult, State, test_template

from azul_plugin_office.plugin_oleinfo import AzulPluginOleInfo


class TestExecute(test_template.TestPlugin):
    PLUGIN_TO_TEST = AzulPluginOleInfo

    def test_variable_boolean(self):
        """Test boolean evaluation on mixed types/values."""
        o = AzulPluginOleInfo()
        self.assertEqual(o._variable_boolean(None), False)
        self.assertEqual(o._variable_boolean(True), True)
        self.assertEqual(o._variable_boolean(False), False)
        self.assertEqual(o._variable_boolean("Yes"), True)
        self.assertEqual(o._variable_boolean("No"), False)
        self.assertEqual(o._variable_boolean("Error"), False)
        self.assertEqual(o._variable_boolean(0), False)
        self.assertEqual(o._variable_boolean(1), True)
        self.assertEqual(o._variable_boolean(9), True)

    def test_malicious_doc(self):
        """Malicious doc containing CVE-2011-0611"""
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
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="b5a51fa855a995e3ec39bd2893e8109cbc8578d313d907339420d4a56745ec6a",
                        features={
                            "document_author": [FV("7")],
                            "document_company": [FV("hust")],
                            "document_created": [FV(datetime.datetime(2011, 4, 4, 6, 50))],
                            "document_last_author": [FV("7")],
                            "document_last_saved": [FV(datetime.datetime(2011, 4, 4, 6, 51))],
                            "document_page_count": [FV(1)],
                            "ole_application": [FV("Microsoft Office Word")],
                            "ole_author": [FV("7")],
                            "ole_codepage": [FV(936)],
                            "ole_codepage_doc": [FV(936)],
                            "ole_company": [FV("hust")],
                            "ole_contains": [FV("FLASH_OBJECTS"), FV("OLE_OBJECTS")],
                            "ole_count_flash": [FV(1)],
                            "ole_count_lines": [FV(1)],
                            "ole_count_pages": [FV(1)],
                            "ole_count_paragraphs": [FV(1)],
                            "ole_edit_duration": [FV(60)],
                            "ole_revision": [FV("2")],
                            "ole_saved_by": [FV("7")],
                            "ole_template": [FV("Normal.dot")],
                            "ole_time_created": [FV(datetime.datetime(2011, 4, 4, 6, 50))],
                            "ole_time_saved": [FV(datetime.datetime(2011, 4, 4, 6, 51))],
                            "ole_version": [FV(727256)],
                        },
                    )
                ],
            ),
        )

    def test_xls(self):
        """Malicious xls containing CVE-2008-3005"""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "afe6b95ad95bc689c356f34ec8d9094c495e4af57c932ac413b65ef132063acc",
                        "Malicious Microsoft Excel document, cve-2008-3005",
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
                        entity_id="afe6b95ad95bc689c356f34ec8d9094c495e4af57c932ac413b65ef132063acc",
                        features={
                            "document_created": [FV(datetime.datetime(1996, 12, 17, 1, 32, 42))],
                            "document_last_saved": [FV(datetime.datetime(2009, 5, 11, 2, 39, 41))],
                            "ole_application": [FV("Microsoft Excel")],
                            "ole_codepage": [FV(936)],
                            "ole_codepage_doc": [FV(936)],
                            "ole_time_created": [FV(datetime.datetime(1996, 12, 17, 1, 32, 42))],
                            "ole_time_saved": [FV(datetime.datetime(2009, 5, 11, 2, 39, 41))],
                            "ole_version": [FV(730895)],
                        },
                    )
                ],
            ),
        )

    def test_corrupt_ole(self):
        """Corrupted OLE2 stream"""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "87b190a0dca15304bbb062329121cebc48b758e336984af1c249486359000ff9",
                        "Malicious Microsoft Excel spreadsheet, cv2-2009-3129.",
                    ),
                )
            ]
        )
        # latest oletools seems to handle this now.. possibly ignores bad streams?
        # used to check for 'ole_error' feature being set
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="87b190a0dca15304bbb062329121cebc48b758e336984af1c249486359000ff9",
                        features={
                            "document_created": [FV(datetime.datetime(1996, 12, 17, 1, 32, 42))],
                            "document_last_author": [FV("qq")],
                            "document_last_saved": [FV(datetime.datetime(2009, 11, 26, 3, 35, 15))],
                            "document_title": [FV("   ")],
                            "ole_application": [FV("Microsoft Excel")],
                            "ole_codepage": [FV(936)],
                            "ole_codepage_doc": [FV(936)],
                            "ole_saved_by": [FV("qq")],
                            "ole_time_created": [FV(datetime.datetime(1996, 12, 17, 1, 32, 42))],
                            "ole_time_saved": [FV(datetime.datetime(2009, 11, 26, 3, 35, 15))],
                            "ole_title": [FV("   ")],
                            "ole_version": [FV(730895)],
                        },
                    )
                ],
            ),
        )

    def test_thumbnail(self):
        """Powerpoint OLE2 with thumbnail"""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "ecc272ffbe10f93a5fb6ec3b652fc779714a562148c1c285598c8f9cf9547721",
                        "Malicious Microsoft PowerPoint document with malicious thumbnail, malware family upof.",
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
                        entity_id="ecc272ffbe10f93a5fb6ec3b652fc779714a562148c1c285598c8f9cf9547721",
                        features={
                            "document_author": [FV("DELL")],
                            "document_created": [FV(datetime.datetime(2008, 1, 5, 19, 5, 8, 312000))],
                            "document_last_author": [FV("DELL")],
                            "document_last_saved": [FV(datetime.datetime(2012, 1, 29, 11, 44, 3, 958000))],
                            "document_title": [FV("Diapositiva 1")],
                            "document_word_count": [FV(79)],
                            "ole_application": [FV("Microsoft Office PowerPoint")],
                            "ole_author": [FV("DELL")],
                            "ole_codepage": [FV(1252)],
                            "ole_codepage_doc": [FV(1252)],
                            "ole_count_paragraphs": [FV(13)],
                            "ole_count_slides": [FV(3)],
                            "ole_count_words": [FV(79)],
                            "ole_edit_duration": [FV(13842)],
                            "ole_presentation_target": [FV("On-screen Show (4:3)")],
                            "ole_revision": [FV("25")],
                            "ole_saved_by": [FV("DELL")],
                            "ole_thumbnail_hash": [
                                FV("cb07c4620201facd246f7c34aec27fd0059945810ed792b3b4f7926e8edcebaf")
                            ],
                            "ole_time_created": [FV(datetime.datetime(2008, 1, 5, 19, 5, 8, 312000))],
                            "ole_time_saved": [FV(datetime.datetime(2012, 1, 29, 11, 44, 3, 958000))],
                            "ole_title": [FV("Diapositiva 1")],
                            "ole_version": [FV(917504)],
                        },
                    )
                ],
            ),
        )

    def test_corrupt_docsummary(self):
        """OLE2 with corrupt DocumentSummaryInforomation stream"""
        # appears latest oletools now handles without raising error
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "3b761e53fdc7af022501f8cb079e55346a7ed08c7c73e097ee7dc161588471e1",
                        "Malicious Microsoft Excel file with a bad document summary stream.",
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
                        entity_id="3b761e53fdc7af022501f8cb079e55346a7ed08c7c73e097ee7dc161588471e1",
                        features={
                            "document_created": [FV(datetime.datetime(1996, 12, 17, 1, 32, 42))],
                            "document_last_author": [FV("qq")],
                            "document_last_saved": [FV(datetime.datetime(2009, 11, 26, 3, 35, 15))],
                            "document_title": [FV("   ")],
                            "ole_application": [FV("Microsoft Excel")],
                            "ole_codepage": [FV(936)],
                            "ole_saved_by": [FV("qq")],
                            "ole_time_created": [FV(datetime.datetime(1996, 12, 17, 1, 32, 42))],
                            "ole_time_saved": [FV(datetime.datetime(2009, 11, 26, 3, 35, 15))],
                            "ole_title": [FV("   ")],
                        },
                    )
                ],
            ),
        )

    def test_openoffice_doc(self):
        """Libre/OpenOffice doc saved in OLE2 format."""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "6b8e5e0d8f20add0c19980c35b373e58412248629db320afd20c026a40a67df9", "Open office Document."
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
                        entity_id="6b8e5e0d8f20add0c19980c35b373e58412248629db320afd20c026a40a67df9",
                        features={
                            "document_author": [FV("user1111 ")],
                            "document_created": [FV(datetime.datetime(2014, 2, 3, 1, 10, 52))],
                            "document_last_saved": [FV(datetime.datetime(1601, 1, 1, 0, 0))],
                            "ole_author": [FV("user1111 ")],
                            "ole_codepage": [FV(-535)],
                            "ole_codepage_doc": [FV(-535)],
                            "ole_revision": [FV("0")],
                            "ole_time_created": [FV(datetime.datetime(2014, 2, 3, 1, 10, 52))],
                            "ole_time_printed": [FV(datetime.datetime(1601, 1, 1, 0, 0))],
                            "ole_time_saved": [FV(datetime.datetime(1601, 1, 1, 0, 0))],
                        },
                    )
                ],
            ),
        )

    def test_partial_ole(self):
        """Correct ole file header, but cannot open file"""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "a3d6d98567725d271580e3264ce32e5f5298d9de52cbd5a0d69771087aa4e1a4",
                        "Malicious PowerPoint.",
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
                        features={"ole_error": [FV("incomplete OLE sector")]},
                    )
                ],
            ),
        )

    def test_non_ascii_ole(self):
        """OLE with non-ASCII metadata."""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "34dabb17ce0df81d8e4653ef8a664ec4105f6a9a432695a89ee432fcfb266726",
                        "Malicious MSI with non ascii metadata, malware family leonem.",
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
                        entity_id="34dabb17ce0df81d8e4653ef8a664ec4105f6a9a432695a89ee432fcfb266726",
                        features={
                            "document_author": [FV("Microsoft")],
                            "document_created": [FV(datetime.datetime(2024, 1, 24, 0, 14, 3, 53000))],
                            "document_last_saved": [FV(datetime.datetime(2024, 1, 24, 0, 14, 3, 53000))],
                            "document_page_count": [FV(450)],
                            "document_title": [FV("Installation Database")],
                            "document_word_count": [FV(10)],
                            "ole_application": [FV("Aplicação Windows")],
                            "ole_author": [FV("Microsoft")],
                            "ole_codepage": [FV(1252)],
                            "ole_comments": [FV("Aplicação Windows")],
                            "ole_count_pages": [FV(450)],
                            "ole_count_words": [FV(10)],
                            "ole_keywords": [FV("Installer, MSI, Database")],
                            "ole_revision": [FV("{E345A3F5-4F12-4F85-8AE0-AD9008F3E5A1}")],
                            "ole_subject": [FV("Aplicação Windows")],
                            "ole_template": [FV(";1046")],
                            "ole_time_created": [FV(datetime.datetime(2024, 1, 24, 0, 14, 3, 53000))],
                            "ole_time_printed": [FV(datetime.datetime(2024, 1, 24, 0, 14, 3, 53000))],
                            "ole_time_saved": [FV(datetime.datetime(2024, 1, 24, 0, 14, 3, 53000))],
                            "ole_title": [FV("Installation Database")],
                        },
                    )
                ],
            ),
        )

    def test_ole_with_security(self):
        """OLE with the security flag set."""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "69f40c2f6a4540550f934e0b2f9a354629d3835b30fd13293c2f6a6b97202159",
                        "Malicious Microsoft Excel document, cve-2017-0199.",
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
                        entity_id="69f40c2f6a4540550f934e0b2f9a354629d3835b30fd13293c2f6a6b97202159",
                        features={
                            "document_created": [FV(datetime.datetime(2006, 9, 16, 0, 0))],
                            "document_last_saved": [FV(datetime.datetime(2024, 1, 25, 6, 41, 39))],
                            "ole_application": [FV("Microsoft Excel")],
                            "ole_codepage": [FV(1252)],
                            "ole_codepage_doc": [FV(1252)],
                            "ole_contains": [FV("VBA_MACROS")],
                            "ole_security": [FV("Password protected")],
                            "ole_time_created": [FV(datetime.datetime(2006, 9, 16, 0, 0))],
                            "ole_time_saved": [FV(datetime.datetime(2024, 1, 25, 6, 41, 39))],
                            "ole_version": [FV(786432)],
                            "tag": [FV("ENCRYPTED")],
                        },
                    )
                ],
            ),
        )

    def test_ole_with_numeric_author(self):
        """OLE with an integer author field."""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "a4d2138624f8eebbbd665597b1b9e7c3817c374e0e27327cf8acf1b5c57a4b10",
                        "Malicious MSI with numeric author, malware family zusy.",
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
                        entity_id="a4d2138624f8eebbbd665597b1b9e7c3817c374e0e27327cf8acf1b5c57a4b10",
                        features={
                            "document_author": [FV("6765")],
                            "document_created": [FV(datetime.datetime(2024, 1, 25, 12, 6, 48))],
                            "document_last_saved": [FV(datetime.datetime(2024, 1, 25, 12, 6, 48))],
                            "document_page_count": [FV(200)],
                            "document_title": [FV("Installation Database")],
                            "document_word_count": [FV(10)],
                            "ole_application": [FV("Windows Installer XML Toolset (3.11.1.2318)")],
                            "ole_author": [FV("6765")],
                            "ole_codepage": [FV(1252)],
                            "ole_comments": [
                                FV(
                                    "This installer database contains the logic and data required to install m_20240125_140644_b96d7ba736fc49748aad5dd93b9173b9."
                                )
                            ],
                            "ole_count_pages": [FV(200)],
                            "ole_count_words": [FV(10)],
                            "ole_keywords": [FV("Installer")],
                            "ole_revision": [FV("{1400EFFC-F877-4169-A942-A58083759154}")],
                            "ole_security": [FV("Read-only recommended")],
                            "ole_subject": [FV("m_20240125_140644_b96d7ba736fc49748aad5dd93b9173b9")],
                            "ole_template": [FV("Intel;1033")],
                            "ole_time_created": [FV(datetime.datetime(2024, 1, 25, 12, 6, 48))],
                            "ole_time_saved": [FV(datetime.datetime(2024, 1, 25, 12, 6, 48))],
                            "ole_title": [FV("Installation Database")],
                        },
                    )
                ],
            ),
        )

    def test_ole_unicode_application_and_version(self):
        """Regression test that fails with an Invalid Plugin Output error because the ole_application and ole_revision are long unicode values."""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "3f95f256b75c853ff5fa9b5133903d6a7d99a0589b3fd72fb2f9e76dc672be82",
                        "Benign Microsoft OLE file with a very long application revision.",
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
                        entity_id="3f95f256b75c853ff5fa9b5133903d6a7d99a0589b3fd72fb2f9e76dc672be82",
                        features={
                            "document_created": [FV(datetime.datetime(2017, 5, 30, 16, 43, 41, 865000))],
                            "document_last_saved": [FV(datetime.datetime(2017, 10, 3, 13, 59, 0, 375000))],
                            "document_page_count": [FV(1)],
                            "ole_application": [
                                FV(
                                    "Crystal Reports\x00G\x00遴\x00\uffff\uffff\x03\x00\x08\x9fà\x00\x01\t̀䠲\x00\x00䠡\x00\x00\x05\x00ć\x04\x00䠡\x00ୁ Ìà\x9f\x00\x00à\x9f\x00\x00(\x00\x9f\x00à\x00\x01\x08\x00\x00谀\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00:\x00\x00:㨀:㨺:f\x00㩦\x00\x00f㩦f昀f昺f晦f㪐"
                                )
                            ],
                            "ole_codepage": [FV(1252)],
                            "ole_count_pages": [FV(1)],
                            "ole_edit_duration": [FV(2886)],
                            "ole_revision": [
                                FV(
                                    "10\x00\x00@\x00鍐뢼\x06\x00@\x00\x00\x00\x00\x00@\x00ꉰ썽㱏Ǔ@\x00�\ue544�ǒ\x03\x00\x01\x00\x03\x00\x00\x00\x03\x00\x00\x00\x1f\x00\x10\x00Crystal Reports\x00G\x00遴\x00\uffff\uffff\x03\x00\x08\x9fà\x00\x01\t̀䠲\x00\x00䠡\x00\x00\x05\x00ć\x04\x00䠡\x00ୁ Ìà\x9f\x00\x00à\x9f\x00\x00("
                                )
                            ],
                            "ole_thumbnail_hash": [
                                FV("085574739f89eb5402771cc136200096d74cc403469bad4293310888151b6a55")
                            ],
                            "ole_time_created": [FV(datetime.datetime(2017, 5, 30, 16, 43, 41, 865000))],
                            "ole_time_printed": [FV(datetime.datetime(1601, 1, 1, 0, 0))],
                            "ole_time_saved": [FV(datetime.datetime(2017, 10, 3, 13, 59, 0, 375000))],
                        },
                    )
                ],
            ),
        )
