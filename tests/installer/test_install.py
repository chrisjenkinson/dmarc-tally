"""Offline release/install contract. AWS and DNS are never contacted by CI."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import unittest
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("dmarc_install", ROOT / "scripts/install.py")
install = importlib.util.module_from_spec(spec)
spec.loader.exec_module(install)


def configured():
    data = json.loads((ROOT / "config/production.example.json").read_text())
    data["aws"].update(account_id="123456789012", profile="sample-profile")
    data["monitored_domains"] = ["sender.fake", "other.fake"]
    data["email"].update(
        administrator="admin@fake.tld", alerts="alerts@fake.tld",
        sender="login@fake.tld", sender_identity="fake.tld",
        receiving="aggregate@dmarc.fake.tld",
        receipt_rule_set="private_rules",
    )
    return data


class ConfigurationTests(unittest.TestCase):
    def test_initializer_creates_private_ignored_config_without_overwriting(self):
        import os
        import tempfile
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory) / ".local"
            config_path = private / "production.json"
            with patch.object(install, "LOCAL", private), patch.object(install, "CONFIG", config_path):
                install.init()
                self.assertEqual(json.loads(config_path.read_text())["_note"].startswith("COPY"), True)
                self.assertEqual(os.stat(config_path).st_mode & 0o777, 0o600)
                with self.assertRaises(install.InstallError):
                    install.init()
                self.assertEqual(config_path.read_bytes(), (private / "production.json").read_bytes())

    def test_public_example_is_intentionally_not_deployable(self):
        example = json.loads((ROOT / "config/production.example.json").read_text())
        with self.assertRaises(install.InstallError):
            install.validate_config(example)
        self.assertIn("/.local/", (ROOT / ".gitignore").read_text())

    def test_clean_local_configuration_is_valid(self):
        cfg = configured()
        install.validate_config(cfg)
        self.assertEqual(cfg["monitored_domains"], ["sender.fake", "other.fake"])

    def test_rejects_bad_account_placeholder_duplicates_and_injected_values(self):
        cases = [
            ("aws", "account_id", "000000000000"),
            ("aws", "profile", "a\nx"),
            ("aws", "region", "not-a-region"),
            ("email", "administrator", "admin@example.invalid"),
            ("email", "alerts", "one other@fake.tld"),
            ("email", "receiving", "without-at-symbol"),
            ("email", "receipt_rule_set", "space in rule"),
            ("email", "sender_identity", "bad/identity"),
        ]
        for group, key, value in cases:
            with self.subTest(group=group, key=key):
                cfg = configured()
                cfg[group][key] = value
                with self.assertRaises(install.InstallError):
                    install.validate_config(cfg)
        for domains in ([], ["sender.fake", "sender.fake"], ["hello bad"], ["example.invalid"]):
            with self.subTest(domains=domains):
                cfg = configured()
                cfg["monitored_domains"] = domains
                with self.assertRaises(install.InstallError):
                    install.validate_config(cfg)

    def test_stack_parameters_use_only_local_values_and_expected_outputs(self):
        cfg = configured()
        outputs = {
            "artifacts": {"ArtifactBucket": "private-artifact-bucket"},
            "ingestion": {"ReportsTable": "reports-table", "IntakeBucket": "private-intake"},
            "web": {"WebFunctionArn": "arn:aws:lambda:ap-southeast-2:123456789012:function:web"},
        }
        release = {
            "ingest": {"key": "releases/pinned/ingest/sha/bootstrap.zip"},
            "web": {"key": "releases/pinned/web/sha/bootstrap.zip"},
        }
        self.assertEqual(install.parameters("artifacts", cfg, outputs, release), {})
        ingest = install.parameters("ingestion", cfg, outputs, release)
        self.assertEqual(ingest["MonitoredDomains"], "sender.fake,other.fake")
        self.assertEqual(ingest["CodeBucket"], "private-artifact-bucket")
        self.assertEqual(ingest["NotificationEmail"], "alerts@fake.tld")
        self.assertEqual(install.parameters("web", cfg, outputs, release)["PublicOrigin"],
                         install.BOOTSTRAP_ORIGIN)
        outputs["edge"] = {"WebHttpsOrigin": "https://api-id.execute-api.ap-southeast-2.amazonaws.com"}
        self.assertEqual(install.parameters("web", cfg, outputs, release)["PublicOrigin"],
                         outputs["edge"]["WebHttpsOrigin"])
        self.assertEqual(install.parameters("edge", cfg, outputs, release)["WebFunctionArn"],
                         outputs["web"]["WebFunctionArn"])
        ses = install.parameters("receiving", cfg, outputs, release)
        self.assertEqual(ses["EnableReceiving"], "false")
        self.assertEqual(ses["IntakeBucketName"], "private-intake")
        self.assertEqual(ses["ReceivingAddress"], "aggregate@dmarc.fake.tld")

    def test_unsafe_cloudformation_operations_must_fail_closed(self):
        safe = [
            {"ResourceChange": {"Action": "Add", "LogicalResourceId": "SafeLog", "ResourceType": "AWS::Logs::LogGroup"}},
            {"ResourceChange": {"Action": "Modify", "LogicalResourceId": "Web", "ResourceType": "AWS::Lambda::Function", "Replacement": "False"}},
        ]
        install.check_changes(safe)
        for risky in [
            {"Action": "Remove", "LogicalResourceId": "Auth", "ResourceType": "AWS::DynamoDB::Table"},
            {"Action": "Modify", "LogicalResourceId": "Intake", "ResourceType": "AWS::S3::Bucket", "Replacement": "Conditional"},
            {"Action": "Modify", "LogicalResourceId": "Auth", "ResourceType": "AWS::DynamoDB::Table", "Replacement": "True"},
            {"Action": "Import", "LogicalResourceId": "X", "ResourceType": "AWS::S3::Bucket"},
            {"Action": "Modify", "LogicalResourceId": "Reports", "ResourceType": "AWS::DynamoDB::Table", "Replacement": "False"},
        ]:
            with self.subTest(risky=risky), self.assertRaises(install.InstallError):
                install.check_changes([{"ResourceChange": risky}])

    def test_release_archive_must_be_x86_linux_bootstrap(self):
        payload = bytearray(64)
        payload[:4] = b"\x7fELF"
        payload[4] = 2
        payload[18:20] = (62).to_bytes(2, "little")
        stream = io.BytesIO()
        with ZipFile(stream, "w") as archive:
            entry = ZipInfo("bootstrap")
            entry.external_attr = 0o755 << 16
            archive.writestr(entry, payload)
        install.verify_bootstrap_zip(stream.getvalue())
        with self.assertRaises(install.InstallError):
            install.verify_bootstrap_zip(b"not a zip")
        with self.assertRaises(install.InstallError):
            install.verify_bootstrap_zip(stream.getvalue().replace(b"\x7fELF", b"XXXX", 1))

    def test_release_keys_include_pinned_commit_and_content_digest(self):
        commit = "a" * 40
        checksum = "b" * 64
        self.assertEqual(
            install.artifact_key(commit, "web", checksum),
            "releases/" + commit + "/web/" + checksum + "/bootstrap.zip",
        )


if __name__ == "__main__":
    unittest.main()
