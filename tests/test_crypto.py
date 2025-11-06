"""
Office Decryptor Test Suite.

Test decryption of various office doc formats/algorithms and handling of
default configured and event supplied passwords.
"""

from azul_runner import (
    FV,
    APIFeatureValue,
    Event,
    EventData,
    EventParent,
    JobResult,
    State,
    test_template,
)

from azul_plugin_office.plugin_crypto import AzulPluginOfficeDecryptor


class TestExecute(test_template.TestPlugin):
    """Plugin test wrapper."""

    PLUGIN_TO_TEST = AzulPluginOfficeDecryptor

    def test_unencrypted_word_doc(self):
        """Unencrypted MS Word 2003 Document with benign macro."""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "ffc7df1b29a93d861ad70ed3d5bccdfa4312140185520cc6a58cce5b9e11215a",
                        "Benign auto open Macro document.",
                    ),
                )
            ]
        )
        self.assertJobResult(result, JobResult(state=State(State.Label.OPT_OUT)))

    def test_benign_ecma_standard_unknown_password(self):
        """Benign ECMA-376 Standard from msoffcrypto-tool test cases."""
        # we want to ensure we still create feature for the details we can extract
        # even when missing the password to decrypt the document
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "d265dcf02f7d552486229b8c67a627ef3752fe6802b02fd2d2d485fcfbbac5de",
                        "Benign Microsoft Word document, ecma standard.",
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
                        entity_id="d265dcf02f7d552486229b8c67a627ef3752fe6802b02fd2d2d485fcfbbac5de",
                        features={
                            "office_encrypted_format": [FV("ooxml")],
                            "office_encryption_algorithm": [FV("AES-128")],
                            "office_encryption_hash_algorithm": [FV("SHA1")],
                            "office_encryption_key_size": [FV(128)],
                            "office_encryption_method": [FV("ECMA-376 Standard")],
                            "office_encryption_provider": [
                                FV("Microsoft Enhanced RSA and AES Cryptographic Provider")
                            ],
                            "office_encryption_salt": [FV("e88266490c5bd1eebd2b4394e3f830ef", label="verifier")],
                            "office_encryption_verifier": [FV("516f732e966fac17b1c5d7d8cc36c928")],
                            "office_encryption_verifier_hash": [
                                FV("2b6168dabe2911ad2bd37c1746745c14d3cf1bb140a48f4e6f3d23880872b16a")
                            ],
                            "tag": [FV("encrypted")],
                        },
                    )
                ],
            ),
        )

    def test_benign_ecma_standard_supplied_password(self):
        """Benign ECMA-376 Standard from msoffcrypto-tool test cases - with password."""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "d265dcf02f7d552486229b8c67a627ef3752fe6802b02fd2d2d485fcfbbac5de",
                        "Benign Microsoft Word document, ecma standard.",
                    ),
                ),
                ("password_dictionary", b"foobar\nmonkeys\nPassword1234_"),
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="d265dcf02f7d552486229b8c67a627ef3752fe6802b02fd2d2d485fcfbbac5de",
                        features={
                            "office_encrypted_format": [FV("ooxml")],
                            "office_encryption_algorithm": [FV("AES-128")],
                            "office_encryption_hash_algorithm": [FV("SHA1")],
                            "office_encryption_key_size": [FV(128)],
                            "office_encryption_method": [FV("ECMA-376 Standard")],
                            "office_encryption_provider": [
                                FV("Microsoft Enhanced RSA and AES Cryptographic Provider")
                            ],
                            "office_encryption_salt": [FV("e88266490c5bd1eebd2b4394e3f830ef", label="verifier")],
                            "office_encryption_verifier": [FV("516f732e966fac17b1c5d7d8cc36c928")],
                            "office_encryption_verifier_hash": [
                                FV("2b6168dabe2911ad2bd37c1746745c14d3cf1bb140a48f4e6f3d23880872b16a")
                            ],
                            "office_password": [FV("Password1234_")],
                            "office_secret_key": [FV("40b13a71f90b966e375408f2d181a1aa")],
                            "password": [FV("Password1234_")],
                            "tag": [FV("encrypted")],
                        },
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="d265dcf02f7d552486229b8c67a627ef3752fe6802b02fd2d2d485fcfbbac5de",
                        ),
                        entity_type="binary",
                        entity_id="ca1c0ebb465553361b9034e696d4081df0a2d41918f820060325b3ca634eb69b",
                        relationship={"action": "decrypted", "algorithm": "AES-128", "password": "Password1234_"},
                        data=[
                            EventData(
                                hash="ca1c0ebb465553361b9034e696d4081df0a2d41918f820060325b3ca634eb69b",
                                label="content",
                            )
                        ],
                        features={"tag": [FV("decrypted_doc")]},
                    ),
                ],
                data={"ca1c0ebb465553361b9034e696d4081df0a2d41918f820060325b3ca634eb69b": b""},
            ),
        )

    def test_malicious_ecma_agile(self):
        """Malicious xlsx with Excel hardcoded/known password 'VelvetSweatshop'."""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "be0557bec0622a480e392e97bd338d826423ba64c9b72243150d0a025b9f0543",
                        "Malicious Microsoft Word document, cve-2017-11882.",
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
                        entity_id="be0557bec0622a480e392e97bd338d826423ba64c9b72243150d0a025b9f0543",
                        features={
                            "office_encrypted_format": [FV("ooxml")],
                            "office_encryption_algorithm": [FV("AES-128")],
                            "office_encryption_hash_algorithm": [FV("SHA1")],
                            "office_encryption_key_size": [FV(128)],
                            "office_encryption_method": [FV("ECMA-376 Agile")],
                            "office_encryption_salt": [
                                FV("c2ebeb13e0020ae0a0930aa41877f562", label="keydata"),
                                FV("e20d1218014cf6d9ef8f97f9e0625191", label="password"),
                            ],
                            "office_encryption_spin_count": [FV(100000)],
                            "office_encryption_verifier": [FV("31c6fb53f44b5bb7b1a9b9134a07f181")],
                            "office_encryption_verifier_hash": [
                                FV("9d1974b906c2f308160407bdce3c738783d96a6fa80eec7030dca6c5cdfd473a")
                            ],
                            "office_password": [FV("VelvetSweatshop")],
                            "office_secret_key": [FV("f1d86644d552e97fd0d946def97f5382")],
                            "password": [FV("VelvetSweatshop")],
                            "tag": [FV("encrypted")],
                        },
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="be0557bec0622a480e392e97bd338d826423ba64c9b72243150d0a025b9f0543",
                        ),
                        entity_type="binary",
                        entity_id="bfc95db60438a34241e2d837d040e7e73f9fa44eb0fa9ab2906406562b3cd4d4",
                        relationship={"action": "decrypted", "algorithm": "AES-128", "password": "VelvetSweatshop"},
                        data=[
                            EventData(
                                hash="bfc95db60438a34241e2d837d040e7e73f9fa44eb0fa9ab2906406562b3cd4d4",
                                label="content",
                            )
                        ],
                        features={"tag": [FV("decrypted_doc")]},
                    ),
                ],
                data={"bfc95db60438a34241e2d837d040e7e73f9fa44eb0fa9ab2906406562b3cd4d4": b""},
            ),
        )

    def test_malicious_ecma_standard_with_filename(self):
        """Test reasonable filename passed down to decrypted child."""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "b8591abcadb0b7df43c65b8896ac6432fe70ef5583442644da1ce48d2d5899b8",
                        "Malicious Microsoft Word document, ecma standard, cve-2017-1188",
                    ),
                )
            ],
            feats_in=[
                APIFeatureValue(name="filename", type="filepath", value="abcdef1234567890"),
                APIFeatureValue(name="filename", type="filepath", value="secure.xlsx"),
            ],
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="b8591abcadb0b7df43c65b8896ac6432fe70ef5583442644da1ce48d2d5899b8",
                        features={
                            "office_encrypted_format": [FV("ooxml")],
                            "office_encryption_algorithm": [FV("AES-128")],
                            "office_encryption_hash_algorithm": [FV("SHA1")],
                            "office_encryption_key_size": [FV(128)],
                            "office_encryption_method": [FV("ECMA-376 Standard")],
                            "office_encryption_provider": [
                                FV("Microsoft Enhanced RSA and AES Cryptographic Provider")
                            ],
                            "office_encryption_salt": [FV("dc894b62be515b4c224d835c427e81b4", label="verifier")],
                            "office_encryption_verifier": [FV("939eb5b7302bd1c3c36570e955053bf1")],
                            "office_encryption_verifier_hash": [
                                FV("1fe9c3556aab94317603791485ac463891d2bde0aee3f983aa3063613f2b1bf0")
                            ],
                            "office_password": [FV("VelvetSweatshop")],
                            "office_secret_key": [FV("92f9c273475a5fb9c8701ac6daa6ea3e")],
                            "password": [FV("VelvetSweatshop")],
                            "tag": [FV("encrypted")],
                        },
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="b8591abcadb0b7df43c65b8896ac6432fe70ef5583442644da1ce48d2d5899b8",
                        ),
                        entity_type="binary",
                        entity_id="6766c15eaafa863264cb1761de30ebd0d72eded466a3f84fc3db37292bec55e6",
                        relationship={"action": "decrypted", "algorithm": "AES-128", "password": "VelvetSweatshop"},
                        data=[
                            EventData(
                                hash="6766c15eaafa863264cb1761de30ebd0d72eded466a3f84fc3db37292bec55e6",
                                label="content",
                            )
                        ],
                        features={"filename": [FV("secure.xlsx")], "tag": [FV("decrypted_doc")]},
                    ),
                ],
                data={"6766c15eaafa863264cb1761de30ebd0d72eded466a3f84fc3db37292bec55e6": b""},
            ),
        )

    def test_benign_rc4_doc(self):
        """Test RC4 decryption of doc97."""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "9c5217bea80fb1a7811ad7709dd9bb35f6c639bac7154580dd4c99d54e1fc0e0",
                        "Benign Microsoft Word document with rc4 crypto.",
                    ),
                ),
                ("password_dictionary", b"Password1234_"),
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="9c5217bea80fb1a7811ad7709dd9bb35f6c639bac7154580dd4c99d54e1fc0e0",
                        features={
                            "office_encrypted_format": [FV("doc97")],
                            "office_encryption_algorithm": [FV("RC4")],
                            "office_encryption_hash_algorithm": [FV("SHA1")],
                            "office_encryption_key_size": [FV(128)],
                            "office_encryption_method": [FV("Office Binary RC4 - CryptoAPI")],
                            "office_encryption_salt": [FV("389eb85ba016979b45872262bd473d33", label="password")],
                            "office_encryption_verifier": [FV("ae9b4378c00439b8b41d20a7e60d5472")],
                            "office_encryption_verifier_hash": [FV("55f5f2601bc97515cb1908e1ad706e50c3734500")],
                            "office_password": [FV("Password1234_")],
                            "password": [FV("Password1234_")],
                            "tag": [FV("encrypted")],
                        },
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="9c5217bea80fb1a7811ad7709dd9bb35f6c639bac7154580dd4c99d54e1fc0e0",
                        ),
                        entity_type="binary",
                        entity_id="65eb884be862337c0e51e78bf57be6cb6601040a16055a87d1e4dd3de4c04303",
                        relationship={"action": "decrypted", "algorithm": "RC4", "password": "Password1234_"},
                        data=[
                            EventData(
                                hash="65eb884be862337c0e51e78bf57be6cb6601040a16055a87d1e4dd3de4c04303",
                                label="content",
                            )
                        ],
                        features={"tag": [FV("decrypted_doc")]},
                    ),
                ],
                data={"65eb884be862337c0e51e78bf57be6cb6601040a16055a87d1e4dd3de4c04303": b""},
            ),
        )

    def test_benign_rc4_xls(self):
        """Test RC4 decryption of xls97."""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "b804cba40c27ea88f2ea994b6b7d75145661532f9356e7246d2499f63d58abfe",
                        "Benign Microsoft Excel Spreadsheet with rc4 crypto.",
                    ),
                ),
                ("password_dictionary", b"Password1234_"),
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="b804cba40c27ea88f2ea994b6b7d75145661532f9356e7246d2499f63d58abfe",
                        features={
                            "office_encrypted_format": [FV("xls97")],
                            "office_encryption_algorithm": [FV("RC4")],
                            "office_encryption_hash_algorithm": [FV("SHA1")],
                            "office_encryption_key_size": [FV(128)],
                            "office_encryption_method": [FV("Office Binary RC4 - CryptoAPI")],
                            "office_encryption_salt": [FV("ff6b27f7b025eb08a8aca2c4477cc064", label="password")],
                            "office_encryption_verifier": [FV("b948eea818830e56ce56a60c822e7cb3")],
                            "office_encryption_verifier_hash": [FV("55bb40447d2bae6b938d9ff54366053628abc435")],
                            "office_password": [FV("Password1234_")],
                            "password": [FV("Password1234_")],
                            "tag": [FV("encrypted")],
                        },
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="b804cba40c27ea88f2ea994b6b7d75145661532f9356e7246d2499f63d58abfe",
                        ),
                        entity_type="binary",
                        entity_id="ccaf6545a3abe5b42ca48b6513239d3fcda5ee900d8623eb20e5d604f4702f43",
                        relationship={"action": "decrypted", "algorithm": "RC4", "password": "Password1234_"},
                        data=[
                            EventData(
                                hash="ccaf6545a3abe5b42ca48b6513239d3fcda5ee900d8623eb20e5d604f4702f43",
                                label="content",
                            )
                        ],
                        features={"tag": [FV("decrypted_doc")]},
                    ),
                ],
                data={"ccaf6545a3abe5b42ca48b6513239d3fcda5ee900d8623eb20e5d604f4702f43": b""},
            ),
        )

    def test_benign_rc4_ppt(self):
        """Test RC4 decryption of ppt97."""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "17a57bcbe7cb517c088410fed763ccc58b9b10d23258571c1ab67830d2591a49",
                        "Benign Microsoft PowerPoint with rc4crypto.",
                    ),
                ),
                ("password_dictionary", b"Password1234_"),
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="17a57bcbe7cb517c088410fed763ccc58b9b10d23258571c1ab67830d2591a49",
                        features={
                            "office_encrypted_format": [FV("ppt97")],
                            "office_encryption_algorithm": [FV("RC4")],
                            "office_encryption_hash_algorithm": [FV("SHA1")],
                            "office_encryption_key_size": [FV(128)],
                            "office_encryption_method": [FV("Office Binary RC4 - CryptoAPI")],
                            "office_encryption_salt": [FV("ae1414da8e02732fed62ac2bc9b72087", label="password")],
                            "office_encryption_verifier": [FV("93b4d451c5438c2aebea4591089e0ff6")],
                            "office_encryption_verifier_hash": [FV("b5b49908fee194bfb294ec2e33d7b02f4ac2d0dc")],
                            "office_password": [FV("Password1234_")],
                            "password": [FV("Password1234_")],
                            "tag": [FV("encrypted")],
                        },
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="17a57bcbe7cb517c088410fed763ccc58b9b10d23258571c1ab67830d2591a49",
                        ),
                        entity_type="binary",
                        entity_id="18555251635eaab62a1fce9886026156d375615bd96f5639df7dc005e2488347",
                        relationship={"action": "decrypted", "algorithm": "RC4", "password": "Password1234_"},
                        data=[
                            EventData(
                                hash="18555251635eaab62a1fce9886026156d375615bd96f5639df7dc005e2488347",
                                label="content",
                            )
                        ],
                        features={"tag": [FV("decrypted_doc")]},
                    ),
                ],
                data={"18555251635eaab62a1fce9886026156d375615bd96f5639df7dc005e2488347": b""},
            ),
        )

    def test_benign_rc4_legacy(self):
        """Test RC4 40bit decryption of doc97."""
        # sourced from https://archive.codeplex.com/?p=offcrypto
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "5f94858a80328bec92a0508ce3a9f4d4b088eb4f80a14569f856e7e01b72d642",
                        "Benign Microsoft Word document, rc4.",
                    ),
                ),
                ("password_dictionary", b"not_this_one"),
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="5f94858a80328bec92a0508ce3a9f4d4b088eb4f80a14569f856e7e01b72d642",
                        features={
                            "office_encrypted_format": [FV("doc97")],
                            "office_encryption_algorithm": [FV("RC4")],
                            "office_encryption_hash_algorithm": [FV("MD5")],
                            "office_encryption_key_size": [FV(40)],
                            "office_encryption_method": [FV("Office Binary RC4")],
                            "office_encryption_salt": [FV("7e7cf9ab2e1da803e6d9a42a27b6a8e1", label="password")],
                            "office_encryption_verifier": [FV("082fe03f8de940d2a5dce5cf551b26c0")],
                            "office_encryption_verifier_hash": [FV("708c601bca154007958b8fc4a28884a4")],
                            "office_password": [FV("password")],
                            "password": [FV("password")],
                            "tag": [FV("encrypted")],
                        },
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="5f94858a80328bec92a0508ce3a9f4d4b088eb4f80a14569f856e7e01b72d642",
                        ),
                        entity_type="binary",
                        entity_id="7e5e96a7411bcbe91695b06d590629728c0720fab7b4a33038dce7975d8af05c",
                        relationship={"action": "decrypted", "algorithm": "RC4", "password": "password"},
                        data=[
                            EventData(
                                hash="7e5e96a7411bcbe91695b06d590629728c0720fab7b4a33038dce7975d8af05c",
                                label="content",
                            )
                        ],
                        features={"tag": [FV("decrypted_doc")]},
                    ),
                ],
                data={"7e5e96a7411bcbe91695b06d590629728c0720fab7b4a33038dce7975d8af05c": b""},
            ),
        )

    def test_corrupted_office_file(self):
        """Test a corrupted excel office document."""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "58a2edd6395a65d47fee3a095ec41c92a322e0b123a0e1c8b8314759b1f8ffe6",
                        "Corrupted Microsoft Excel Document.",
                    ),
                ),
            ]
        )
        result.state.message = ""
        self.assertJobResult(
            result,
            JobResult(
                state=State(
                    State.Label.COMPLETED_WITH_ERRORS,
                    message="",
                ),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="58a2edd6395a65d47fee3a095ec41c92a322e0b123a0e1c8b8314759b1f8ffe6",
                        features={"corrupted": [FV("Not a valid office file.")]},
                    )
                ],
            ),
        )
