"""
Office Open XML Info test suite
===============================

"""

import datetime

from azul_runner import FV, Event, JobResult, State, test_template

from azul_plugin_office.plugin_xmlinfo import AzulPluginOpenXmlInfo


class TestExecute(test_template.TestPlugin):
    PLUGIN_TO_TEST = AzulPluginOpenXmlInfo

    def test_malicious_docx(self):
        """Malicious docx with embedded DDEAUTO"""
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
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="bf38288956449bb120bae525b6632f0294d25593da8938bbe79849d6defed5cb",
                        features={
                            "document_author": [FV("Windows User")],
                            "document_created": [
                                FV(datetime.datetime(2017, 10, 10, 10, 45, tzinfo=datetime.timezone.utc))
                            ],
                            "document_last_author": [FV("Windows User")],
                            "document_last_saved": [
                                FV(datetime.datetime(2017, 10, 11, 3, 56, tzinfo=datetime.timezone.utc))
                            ],
                            "document_page_count": [FV(1)],
                            "document_word_count": [FV(64)],
                            "openxml_application": [FV("Microsoft Office Word")],
                            "openxml_application_version": [FV("15.0000", label="Microsoft Office Word")],
                            "openxml_content_type": [
                                FV("png", label="image/png"),
                                FV("rels", label="application/vnd.openxmlformats-package.relationships+xml"),
                                FV("xml", label="application/xml"),
                            ],
                            "openxml_count_chars": [FV(369)],
                            "openxml_count_lines": [FV(3)],
                            "openxml_count_pages": [FV(1)],
                            "openxml_count_paragraphs": [FV(1)],
                            "openxml_count_words": [FV(64)],
                            "openxml_creator": [FV("Windows User")],
                            "openxml_edit_duration": [FV(214)],
                            "openxml_heading_part": [FV("Title")],
                            "openxml_heading_part_count": [FV(1, label="Title")],
                            "openxml_media_objects": [FV(1)],
                            "openxml_modified_by": [FV("Windows User")],
                            "openxml_revision": [FV(35)],
                            "openxml_security": [FV(0)],
                            "openxml_template": [FV("Normal.dotm")],
                            "openxml_time_created": [
                                FV(datetime.datetime(2017, 10, 10, 10, 45, tzinfo=datetime.timezone.utc))
                            ],
                            "openxml_time_modified": [
                                FV(datetime.datetime(2017, 10, 11, 3, 56, tzinfo=datetime.timezone.utc))
                            ],
                        },
                    )
                ],
            ),
        )

    def test_malicious_macro_docx(self):
        """Malicious docx with VBA Macro"""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "034fded5914cdd2eed99c5fb8c6076821370804b96307775b9d23f60cb11b670",
                        "Malicious Microsoft Open XML document.",
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
                        entity_id="034fded5914cdd2eed99c5fb8c6076821370804b96307775b9d23f60cb11b670",
                        features={
                            "document_author": [FV("7")],
                            "document_created": [
                                FV(datetime.datetime(2020, 3, 11, 13, 24, tzinfo=datetime.timezone.utc))
                            ],
                            "document_last_author": [FV("Пользователь Windows")],
                            "document_last_saved": [
                                FV(datetime.datetime(2020, 3, 16, 14, 29, tzinfo=datetime.timezone.utc))
                            ],
                            "document_page_count": [FV(2)],
                            "document_word_count": [FV(0)],
                            "openxml_application": [FV("Microsoft Office Word")],
                            "openxml_application_version": [FV("14.0000", label="Microsoft Office Word")],
                            "openxml_content_type": [
                                FV("bin", label="application/vnd.ms-office.vbaProject"),
                                FV("jpeg", label="image/jpeg"),
                                FV("rels", label="application/vnd.openxmlformats-package.relationships+xml"),
                                FV("xml", label="application/xml"),
                            ],
                            "openxml_count_chars": [FV(2)],
                            "openxml_count_lines": [FV(1)],
                            "openxml_count_pages": [FV(2)],
                            "openxml_count_paragraphs": [FV(1)],
                            "openxml_count_words": [FV(0)],
                            "openxml_creator": [FV("7")],
                            "openxml_edit_duration": [FV(5914)],
                            "openxml_heading_part": [FV("Название")],
                            "openxml_heading_part_count": [FV(1, label="Название")],
                            "openxml_language": [FV("ru-ru")],
                            "openxml_macro_objects": [FV(1)],
                            "openxml_media_objects": [FV(1)],
                            "openxml_modified_by": [FV("Пользователь Windows")],
                            "openxml_revision": [FV(102)],
                            "openxml_security": [FV(0)],
                            "openxml_template": [FV("Normal.dotm")],
                            "openxml_time_created": [
                                FV(datetime.datetime(2020, 3, 11, 13, 24, tzinfo=datetime.timezone.utc))
                            ],
                            "openxml_time_modified": [
                                FV(datetime.datetime(2020, 3, 16, 14, 29, tzinfo=datetime.timezone.utc))
                            ],
                            "tag": [FV("openxml_contains_macros")],
                        },
                    )
                ],
            ),
        )

    def test_wrong_format(self):
        """Corrupt OLE2"""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "a3d6d98567725d271580e3264ce32e5f5298d9de52cbd5a0d69771087aa4e1a4",
                        "Malicious Power Point.",
                    ),
                )
            ],
            verify_input_content=False,
        )
        self.assertJobResult(
            result,
            JobResult(state=State(State.Label.COMPLETED_EMPTY)),
        )

    def test_malformed_malicously_configured_ooxml_file(self):
        """Excel file that raises an invalid argument exception when processed."""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "f695b0420ccca848b8023b05510360a6cc8102677837eaade80622bcd36c47b7",
                        "Malicious Microsoft Open XML.",
                    ),
                )
            ],
        )
        result.state.message = ""
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED_WITH_ERRORS, message=""),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="f695b0420ccca848b8023b05510360a6cc8102677837eaade80622bcd36c47b7",
                        features={
                            "corrupted": [FV("Suspicious file contains '30' files.")],
                            "openxml_failed_to_extract": [FV("File is zip and extraction failed.")],
                        },
                    )
                ],
            ),
        )

    def test_bad_url(self):
        """Test a file that was giving a uri with a bad feature value."""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "bcbd20ebc203acd4915a93b75a1648ca14e947c9084de73a205c7f1557898abc",
                        "Benign microsoft Excel 2007+ XLSX document.",
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
                        entity_id="bcbd20ebc203acd4915a93b75a1648ca14e947c9084de73a205c7f1557898abc",
                        features={
                            "document_author": [FV("RMI@responsiblebusiness.org")],
                            "document_company": [FV("EICC/CFSI")],
                            "document_created": [FV("2010-06-21T21:00:23+00:00")],
                            "document_last_author": [FV("Gavin Wu")],
                            "document_last_saved": [FV("2024-04-26T17:10:57+00:00")],
                            "document_title": [FV("US0683966")],
                            "openxml_alternate_content_path": [
                                FV("C:\\Users\\GavinWu\\Downloads\\2024 CMRT Updates\\")
                            ],
                            "openxml_application": [FV("Microsoft Excel")],
                            "openxml_application_version": [FV("16.0300", label="Microsoft Excel")],
                            "openxml_calc_properties_id": [FV(191029)],
                            "openxml_company": [FV("EICC/CFSI")],
                            "openxml_content_type": [
                                FV(
                                    "bin",
                                    label="application/vnd.openxmlformats-officedocument.spreadsheetml.printerSettings",
                                ),
                                FV("png", label="image/png"),
                                FV("rels", label="application/vnd.openxmlformats-package.relationships+xml"),
                                FV("vml", label="application/vnd.openxmlformats-officedocument.vmlDrawing"),
                                FV("xml", label="application/xml"),
                            ],
                            "openxml_count_sheets": [FV(11)],
                            "openxml_creator": [FV("RMI@responsiblebusiness.org")],
                            "openxml_edit_duration": [FV(0)],
                            "openxml_external_link": [
                                FV(
                                    "http://www.responsiblemineralsinitiative.org/conformant-smelter-refiner-lists/",
                                    label="hyperlink",
                                )
                            ],
                            "openxml_external_link_type": [FV("hyperlink")],
                            "openxml_heading_part": [FV("Named Ranges"), FV("Worksheets")],
                            "openxml_heading_part_count": [FV(9, label="Named Ranges"), FV(11, label="Worksheets")],
                            "openxml_media_objects": [FV(1)],
                            "openxml_modified_by": [FV("Gavin Wu")],
                            "openxml_part_title": [
                                FV("'Product List'!Print_Titles"),
                                FV("'Smelter List'!Metal"),
                                FV("'Smelter List'!Print_Titles"),
                                FV("C"),
                                FV("CL"),
                                FV("Checker"),
                                FV("Declaration"),
                                FV("Declaration!Print_Area"),
                                FV("Declaration!Print_Titles"),
                                FV("Definitions"),
                                FV("Instructions"),
                                FV("L"),
                                FV("LN"),
                                FV("Product List"),
                                FV("Revision"),
                                FV("SL"),
                                FV("Smelter List"),
                                FV("Smelter Look-up"),
                                FV("SmelterIdetifiedForMetal"),
                                FV("SorP"),
                            ],
                            "openxml_printer": [
                                FV("HP Color LaserJet Pro MFP M177"),
                                FV("HP LaserJet 4200"),
                                FV("HP Universal Printing PCL 5"),
                                FV("Microsoft XPS Document Writer"),
                                FV("RICOH Aficio MP C3502"),
                                FV("RICOH Aficio MP C3502 PCL 5c"),
                                FV("RICOH IM C3500 PS"),
                                FV("[A920]Canon LASER SHOT LBP-161"),
                                FV("[A920]Canon LBP8730 LIPSLX"),
                                FV("\\\\EICC-DC1\\Ricoh C3502\x007-6DEF-4"),
                                FV("\\\\EICC-DC1\\Ricoh C3502\x00D-75EC-4"),
                            ],
                            "openxml_revision_document_id": [FV("13_ncr:1_{089740D4-F946-40C5-BE50-61AFE5B29C61}")],
                            "openxml_revision_uid_last_save": [FV("{00000000-0000-0000-0000-000000000000}")],
                            "openxml_security": [FV(0)],
                            "openxml_time_created": [FV("2010-06-21T21:00:23+00:00")],
                            "openxml_time_modified": [FV("2024-04-26T17:10:57+00:00")],
                            "openxml_time_printed": [FV("2015-04-21T20:47:43+00:00")],
                            "openxml_title": [FV("US0683966")],
                            "openxml_version_build": [FV("27425")],
                            "openxml_version_last_edited": [FV("7")],
                            "openxml_version_lowest_edited": [FV("6")],
                        },
                    )
                ],
            ),
        )
