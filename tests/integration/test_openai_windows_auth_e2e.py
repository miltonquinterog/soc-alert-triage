import os
import unittest

from tests.integration.openai_windows_auth_e2e import build_preview, run_real


@unittest.skipUnless(os.getenv("SOC_RUN_OPENAI_INTEGRATION") == "1" and os.getenv("OPENAI_API_KEY") and
    os.getenv("SOC_OPENAI_MODEL") and os.getenv("SOC_OPENAI_APPROVED_REQUEST_ID"),
    "requires explicit integration enablement, OpenAI configuration, and approved preview request ID")
class OpenAIWindowsAuthenticationE2ETests(unittest.TestCase):
    def test_windows_authentication_sequence(self):
        preview, *_ = build_preview()
        self.assertEqual(preview.request_id, os.getenv("SOC_OPENAI_APPROVED_REQUEST_ID"))
        annotation = run_real()
        self.assertEqual("accepted", annotation.validation_status)
