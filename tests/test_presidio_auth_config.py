import importlib.util
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch
import uuid

from werkzeug.security import generate_password_hash


ROOT = Path(__file__).resolve().parents[1]
SERVICE_DIR = ROOT / "presidio_service"
sys.path.insert(0, str(SERVICE_DIR))

from security_config import load_security_config  # noqa: E402


class SecurityConfigTests(unittest.TestCase):
    def valid_env(self):
        return {
            "PRESIDIO_SESSION_SECRET": "s" * 48,
            "PRESIDIO_USERNAME": "operator",
            "PRESIDIO_PASSWORD_HASH": generate_password_hash("correct horse battery staple"),
        }

    def test_missing_configuration_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "PRESIDIO_SESSION_SECRET"):
            load_security_config({})

        with self.assertRaisesRegex(RuntimeError, "PRESIDIO_SESSION_SECRET"):
            self.load_app({})

    def test_weak_or_malformed_security_values_are_rejected(self):
        env = self.valid_env()
        env["PRESIDIO_SESSION_SECRET"] = "too-short"
        with self.assertRaisesRegex(RuntimeError, "at least 32"):
            load_security_config(env)

        env = self.valid_env()
        env["PRESIDIO_PASSWORD_HASH"] = "plaintext-password"
        with self.assertRaisesRegex(RuntimeError, "valid Werkzeug"):
            load_security_config(env)

        env["PRESIDIO_PASSWORD_HASH"] = "scrypt:1:2:3$foo$bar"
        with self.assertRaisesRegex(RuntimeError, "n>=32768"):
            load_security_config(env)

        env["PRESIDIO_PASSWORD_HASH"] = "pbkdf2:sha1:1$foo$bar"
        with self.assertRaisesRegex(RuntimeError, "iterations>=600000"):
            load_security_config(env)

        env["PRESIDIO_PASSWORD_HASH"] = "scrypt:32768:8:1$abcdefghijklmnop$bar"
        with self.assertRaisesRegex(RuntimeError, "valid Werkzeug"):
            load_security_config(env)

        env["PRESIDIO_PASSWORD_HASH"] = (
            "pbkdf2:sha256:600000$abcdefghijklmnop$not-a-hex-digest"
        )
        with self.assertRaisesRegex(RuntimeError, "valid Werkzeug"):
            load_security_config(env)

    def test_valid_configuration_drives_login(self):
        module = self.load_app(self.valid_env())
        client = module.app.test_client()

        rejected = client.post(
            "/login", json={"username": "operator", "password": "wrong"}
        )
        self.assertEqual(rejected.status_code, 401)

        accepted = client.post(
            "/login",
            json={
                "username": "operator",
                "password": "correct horse battery staple",
            },
        )
        self.assertEqual(accepted.status_code, 200)

        state = client.get("/session")
        self.assertEqual(
            state.get_json(), {"authenticated": True, "username": "operator"}
        )

    def test_app_and_ui_contain_no_deployable_default_credentials(self):
        app_source = (SERVICE_DIR / "app.py").read_text()
        template_source = (SERVICE_DIR / "templates" / "index.html").read_text()
        docker_source = (SERVICE_DIR / "Dockerfile").read_text()
        readme_source = (SERVICE_DIR / "README.md").read_text()

        combined = app_source + template_source
        previous_secret = "-".join(("change", "me", "in", "production"))
        previous_password = "".join(("anonymize", "123"))
        self.assertNotIn(previous_secret, combined)
        self.assertNotIn(previous_password, combined)
        self.assertIn("load_security_config()", app_source)
        self.assertIn("check_password_hash", app_source)
        self.assertIn("COPY security_config.py .", docker_source)
        self.assertLess(
            readme_source.index('f"{base_url}/login"'),
            readme_source.index('f"{base_url}/anonymize"'),
        )

    @staticmethod
    def load_app(env):
        analyzer_module = types.ModuleType("presidio_analyzer")
        anonymizer_module = types.ModuleType("presidio_anonymizer")

        class AnalyzerEngine:
            pass

        class AnonymizerEngine:
            pass

        class OperatorConfig:
            def __init__(self, *args, **kwargs):
                pass

        analyzer_module.AnalyzerEngine = AnalyzerEngine
        anonymizer_module.AnonymizerEngine = AnonymizerEngine
        anonymizer_module.OperatorConfig = OperatorConfig

        module_name = f"presidio_app_test_{uuid.uuid4().hex}"
        spec = importlib.util.spec_from_file_location(module_name, SERVICE_DIR / "app.py")
        module = importlib.util.module_from_spec(spec)

        with (
            patch.dict(os.environ, env, clear=True),
            patch.dict(
                sys.modules,
                {
                    "presidio_analyzer": analyzer_module,
                    "presidio_anonymizer": anonymizer_module,
                },
            ),
        ):
            spec.loader.exec_module(module)

        return module


if __name__ == "__main__":
    unittest.main()
