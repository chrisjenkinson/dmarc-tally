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
            "ingestion": {"ReportsTable": "reports-table", "IntakeBucket": "private-intake",
                          "FailureAlertTopicArn": "arn:aws:sns:ap-southeast-2:123456789012:alerts",
                          "FailureAlarmNames": "alarm-one,alarm-two,alarm-three,alarm-four"},
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
        self.assertEqual(install.parameters("web", cfg, outputs, release)["FailureAlarmNames"],
                         "alarm-one,alarm-two,alarm-three,alarm-four")
        outputs["edge"] = {"WebHttpsOrigin": "https://api-id.execute-api.ap-southeast-2.amazonaws.com"}
        self.assertEqual(install.parameters("web", cfg, outputs, release)["PublicOrigin"],
                         outputs["edge"]["WebHttpsOrigin"])
        self.assertEqual(install.parameters("edge", cfg, outputs, release)["WebFunctionArn"],
                         outputs["web"]["WebFunctionArn"])
        ses = install.parameters("receiving", cfg, outputs, release)
        self.assertEqual(ses["EnableReceiving"], "false")
        self.assertEqual(ses["IntakeBucketName"], "private-intake")
        self.assertEqual(ses["ReceivingAddress"], "aggregate@dmarc.fake.tld")

    def test_receiving_create_is_disabled_and_update_preserves_existing_state(self):
        params = {"ReceiptRuleName": "dmarc-tally-reports", "EnableReceiving": "false"}
        create = install.change_set_parameters("receiving", params, "CREATE")
        update = install.change_set_parameters("receiving", params, "UPDATE")
        self.assertIn({"ParameterKey": "EnableReceiving", "ParameterValue": "false"}, create)
        self.assertIn({"ParameterKey": "EnableReceiving", "UsePreviousValue": True}, update)
        self.assertFalse(any("ParameterValue" in entry and
                             entry["ParameterKey"] == "EnableReceiving" for entry in update))
        self.assertIn({"ParameterKey": "ReceiptRuleName", "ParameterValue": "dmarc-tally-reports"},
                      update)
        self.assertEqual(
            install.change_set_parameters("ingestion", {"CodeKey": "x"}, "UPDATE"),
            [{"ParameterKey": "CodeKey", "ParameterValue": "x"}],
        )
        with self.assertRaises(install.InstallError):
            install.change_set_parameters(
                "receiving", {"EnableReceiving": "true"}, "CREATE",
            )
        with self.assertRaises(install.InstallError):
            install.change_set_parameters(
                "receiving", {"EnableReceiving": "true"}, "UPDATE",
            )



    def test_preflight_tools_are_read_only_and_do_not_need_live_aws(self):
        from unittest.mock import patch, Mock

        with (patch.object(install.shutil, "which", side_effect=lambda name:
                    "/usr/bin/" + name if name in {"aws", "git", "cargo"} else None),
              patch.object(install.subprocess, "run",
                           return_value=Mock(returncode=0, stdout="cargo-lambda 1")),
              patch.object(install, "aws_run", side_effect=AssertionError("no AWS needed"))):
            rows = install.preflight_tools()
        states = {name: state for name, state, _ in rows}
        self.assertEqual(states["AWS CLI"], "READY")
        self.assertEqual(states["Rust/Cargo"], "READY")
        self.assertEqual(states["Zig"], "ACTION")
        self.assertEqual(states["cargo-lambda"], "READY")

    def test_preflight_allows_disabled_not_yet_deployed_rule_but_checks_login(self):
        from contextlib import redirect_stdout
        from unittest.mock import patch

        cfg = configured()
        calls = []

        def fake_aws(_cfg, *args, allow_error=False):
            calls.append(args)
            operation = args[:2]
            if operation == ("sts", "get-caller-identity"):
                return {"Account": cfg["aws"]["account_id"]}, ""
            if operation == ("sesv2", "get-account"):
                return {"SendingEnabled": True, "ProductionAccessEnabled": False}, ""
            if operation == ("sesv2", "get-email-identity"):
                identity = args[args.index("--email-identity") + 1]
                if identity in (cfg["email"]["sender_identity"],
                                "fake.tld", "dmarc.fake.tld"):
                    return {"VerificationStatus": "SUCCESS",
                            "VerifiedForSendingStatus": True}, ""
                return {}, "NotFoundException: private admin@example"
            if operation == ("ses", "describe-active-receipt-rule-set"):
                return {"Metadata": {"Name": "private_rules"}, "Rules": []}, ""
            self.fail("Unexpected or mutating AWS call: " + str(operation))

        output = io.StringIO()
        with (patch.object(install, "aws_run", side_effect=fake_aws),
              patch.object(install, "preflight_tools", return_value=[]),
              patch.object(install.shutil, "which", return_value="/usr/bin/aws"),
              redirect_stdout(output)):
            result = install.run_preflight(cfg)
        self.assertTrue(result)
        message = output.getvalue()
        self.assertIn("[READY] SES sandbox administrator recipient:", message)
        self.assertIn("[LATER] Intended SES receipt rule:", message)
        self.assertIn("No detected blockers for the initial login", message)
        self.assertNotIn(cfg["email"]["administrator"], message)
        self.assertNotIn(cfg["email"]["receiving"], message)
        self.assertNotIn("admin@example", message)
        self.assertTrue(all(call[:2] in {
            ("sts", "get-caller-identity"),
            ("sesv2", "get-account"),
            ("sesv2", "get-email-identity"),
            ("ses", "describe-active-receipt-rule-set"),
        } for call in calls))

    def test_preflight_refuses_wrong_account_without_other_aws_lookups(self):
        from unittest.mock import patch
        from contextlib import redirect_stdout
        cfg = configured()
        calls = []

        def fake_aws(_cfg, *args, allow_error=False):
            calls.append(args)
            return {"Account": "999999999999"}, ""

        output = io.StringIO()
        with (patch.object(install, "aws_run", side_effect=fake_aws),
              patch.object(install, "preflight_tools", return_value=[]),
              patch.object(install.shutil, "which", return_value="/usr/bin/aws"),
              redirect_stdout(output)):
            self.assertFalse(install.run_preflight(cfg))
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][:2], ("sts", "get-caller-identity"))
        self.assertIn("[ACTION] AWS account/region:", output.getvalue())
        self.assertNotIn("999999999999", output.getvalue())

    def test_preflight_flags_ses_sandbox_and_bad_sender(self):
        from unittest.mock import patch
        from contextlib import redirect_stdout
        cfg = configured()

        def fake_aws(_cfg, *args, allow_error=False):
            operation = args[:2]
            if operation == ("sts", "get-caller-identity"):
                return {"Account": cfg["aws"]["account_id"]}, ""
            if operation == ("sesv2", "get-account"):
                return {"SendingEnabled": False, "ProductionAccessEnabled": False}, ""
            if operation == ("sesv2", "get-email-identity"):
                return {"VerificationStatus": "PENDING",
                        "VerifiedForSendingStatus": False}, ""
            if operation == ("ses", "describe-active-receipt-rule-set"):
                return {}, ""
            self.fail("Unexpected AWS operation")

        output = io.StringIO()
        with (patch.object(install, "aws_run", side_effect=fake_aws),
              patch.object(install, "preflight_tools", return_value=[]),
              patch.object(install.shutil, "which", return_value="/usr/bin/aws"),
              redirect_stdout(output)):
            self.assertFalse(install.run_preflight(cfg))
        message = output.getvalue()
        for label in ("[ACTION] SES sending access",
                      "[ACTION] SES sender identity",
                      "[ACTION] SES sandbox administrator recipient"):
            self.assertIn(label, message)
        self.assertIn("[LATER] Active SES rule set", message)

    def test_receiving_preflight_marks_overlapping_and_overbroad_rules_for_review(self):
        from unittest.mock import patch
        cfg = configured()
        # Existing active rule must not be displaced by switching rule sets.
        calls = []

        def fake_aws(_cfg, *args, allow_error=False):
            calls.append(args[:2])
            if args[:2] == ("sesv2", "get-email-identity"):
                return {"VerificationStatus": "SUCCESS"}, ""
            if args[:2] == ("ses", "describe-active-receipt-rule-set"):
                return {"Metadata": {"Name": "other-app"},
                        "Rules": [{"Name": "catchall", "Enabled": True,
                                   "Recipients": []}]}, ""
            if args[:2] == ("ses", "describe-receipt-rule-set"):
                return {"Rules": [{"Name": cfg["email"]["receipt_rule_name"],
                                   "Enabled": True,
                                   "Recipients": ["fake.tld"]}]}, ""
            self.fail("Unexpected AWS operation")

        with patch.object(install, "aws_run", side_effect=fake_aws):
            rows = install.preflight_receiving(cfg)
        states = {name: state for name, state, _ in rows}
        self.assertEqual(states["Active SES rule set"], "ACTION")
        self.assertEqual(states["Intended SES receipt rule"], "ACTION")
        self.assertEqual(states["SES rule-order overlap"], "ACTION")
        self.assertEqual(calls.count(("ses", "describe-active-receipt-rule-set")), 1)

    def test_permission_failure_is_unknown_and_raw_errors_never_printed(self):
        from unittest.mock import patch
        from contextlib import redirect_stdout
        cfg = configured()
        leaked = "AccessDenied: admin@private.example secret"
        output = io.StringIO()

        def fake_aws(_cfg, *args, allow_error=False):
            if args[:2] == ("sts", "get-caller-identity"):
                return {"Account": cfg["aws"]["account_id"]}, ""
            return {}, leaked

        with (patch.object(install, "aws_run", side_effect=fake_aws),
              patch.object(install, "preflight_tools", return_value=[]),
              patch.object(install.shutil, "which", return_value="/usr/bin/aws"),
              redirect_stdout(output)):
            self.assertFalse(install.run_preflight(cfg))
        self.assertIn("[UNKNOWN] SES sender identity:", output.getvalue())
        self.assertIn("[UNKNOWN] Active SES receipt rules:", output.getvalue())
        self.assertNotIn(leaked, output.getvalue())
        self.assertNotIn("admin@private.example", output.getvalue())

    def test_status_uses_only_read_only_aws_calls_and_suggests_first_step(self):
        from unittest.mock import patch

        cfg = configured()
        commands = []

        def fake_aws(_cfg, *args, allow_error=False):
            commands.append(args)
            if args[:2] == ("sts", "get-caller-identity"):
                return {"Account": cfg["aws"]["account_id"]}, ""
            if args[:2] == ("cloudformation", "describe-stacks"):
                return {}, "Stack with id does not exist"
            self.fail("Status must not mutate AWS: " + " ".join(args))

        with patch.object(install, "aws_run", side_effect=fake_aws):
            stacks = install.inspect_installation(cfg)
        self.assertEqual(len(commands), 6)
        self.assertTrue(all(c[:2] in (("sts", "get-caller-identity"),
                                       ("cloudformation", "describe-stacks"))
                            for c in commands))
        self.assertTrue(all(stacks[key]["state"] == "missing"
                            for key in install.INSTALL_ORDER))
        self.assertEqual(install.next_install_action(stacks),
                         "Plan/review/apply the artifacts stack.")

        output = io.StringIO()
        from contextlib import redirect_stdout
        with redirect_stdout(output):
            install.show_status(cfg, stacks)
        self.assertIn("artifacts: Not deployed", output.getvalue())
        self.assertNotIn(cfg["email"]["administrator"], output.getvalue())
        self.assertNotIn(cfg["email"]["receiving"], output.getvalue())

    def test_status_recommends_second_web_deployment_and_flags_disabled_receiving(self):
        def component(state="deployed", outputs=None, parameters=None):
            return {"state": state, "outputs": outputs or {},
                    "parameters": parameters or {}, "missing_outputs": ()}
        stacks = {
            "artifacts": component(outputs={"ArtifactBucket": "bucket"}),
            "ingestion": component(outputs={"IntakeBucket": "intake"}),
            "web": component(parameters={"PublicOrigin": install.BOOTSTRAP_ORIGIN}),
            "edge": component(outputs={"WebHttpsOrigin": "https://api.example.test"}),
            "receiving": component(parameters={"EnableReceiving": "false"}),
        }
        self.assertIn("web stack again", install.next_install_action(stacks))
        stacks["web"]["parameters"]["PublicOrigin"] = "https://api.example.test"
        self.assertIn("enable receiving only", install.next_install_action(stacks))
        stacks["receiving"]["parameters"]["EnableReceiving"] = "true"
        self.assertIn("controlled SES-to-S3-to-DynamoDB",
                      install.next_install_action(stacks))
        stacks["ingestion"]["missing_outputs"] = ("FailureAlarmNames",)
        self.assertIn("expected outputs are missing", install.next_install_action(stacks))
        stacks["ingestion"]["missing_outputs"] = ()
        stacks["web"]["state"] = "attention"
        self.assertIn("Inspect the web CloudFormation", install.next_install_action(stacks))

    def test_aws_inspection_distinguishes_missing_failed_and_permission_errors(self):
        from unittest.mock import patch
        cfg = configured()

        def configured_result(_cfg, *args, allow_error=False):
            self.assertEqual(args[:2], ("cloudformation", "describe-stacks"))
            return {"Stacks": [{
                "StackName": install.stack_name(cfg, "receiving"),
                "StackStatus": "UPDATE_ROLLBACK_COMPLETE",
                "Parameters": [{"ParameterKey": "EnableReceiving",
                                "ParameterValue": "true"}],
            }]}, ""
        with patch.object(install, "aws_run", side_effect=configured_result):
            self.assertEqual(install.inspect_installation_stack(cfg, "receiving")["state"],
                             "attention")
        with patch.object(install, "aws_run", return_value=({}, "AccessDenied")):
            self.assertEqual(install.inspect_installation_stack(cfg, "receiving")["state"],
                             "unavailable")
        with patch.object(install, "aws_run", return_value=(
                {"Stacks": [{"StackName": install.stack_name(cfg, "receiving"),
                             "StackStatus": "REVIEW_IN_PROGRESS"}]}, "")):
            self.assertEqual(install.inspect_installation_stack(cfg, "receiving")["state"],
                             "pending")

    def test_summary_is_explicit_private_and_release_matches_both_deployed_keys(self):
        from contextlib import redirect_stdout
        from tempfile import TemporaryDirectory
        from unittest.mock import patch
        cfg = configured()
        commit = "a" * 40
        web_key = f"releases/{commit}/web/{'b' * 64}/bootstrap.zip"
        ingest_key = f"releases/{commit}/ingest/{'c' * 64}/bootstrap.zip"
        stacks = {part: {"state": "deployed", "outputs": {},
                         "parameters": {}, "missing_outputs": ()}
                  for part in install.INSTALL_ORDER}
        stacks["edge"]["outputs"] = {
            "WebHttpsOrigin": "https://api.example.test"}
        stacks["web"]["parameters"] = {
            "PublicOrigin": "https://api.example.test", "CodeKey": web_key}
        stacks["ingestion"]["parameters"] = {"CodeKey": ingest_key}
        stacks["receiving"]["parameters"] = {"EnableReceiving": "true"}
        with TemporaryDirectory() as directory:
            manifest = Path(directory) / "release.json"
            manifest.write_text(json.dumps({
                "commit": commit,
                "artifacts": {"web": {"key": web_key}, "ingest": {"key": ingest_key}},
            }))
            with patch.object(install, "MANIFEST", manifest):
                output = io.StringIO()
                with redirect_stdout(output):
                    install.show_summary(cfg, stacks)
                value = output.getvalue()
        self.assertIn("PRIVATE installation summary", value)
        self.assertIn("https://api.example.test", value)
        self.assertIn(cfg["email"]["administrator"], value)
        self.assertIn(cfg["email"]["receiving"], value)
        self.assertIn(cfg["email"]["alerts"], value)
        self.assertIn(commit[:12], value)
        self.assertIn("both deployed Lambda CodeKeys match", value)
        self.assertIn("Next action:", value)
        self.assertNotIn("000000000000", value)

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

    def test_plan_does_not_execute_and_apply_requires_exact_local_approval(self):
        import contextlib
        import tempfile
        from unittest.mock import patch

        cfg = configured()
        approved_arn = "arn:aws:cloudformation:ap-southeast-2:123456789012:changeSet/manual-a/123"
        changes = [{"ResourceChange": {
            "Action": "Add", "LogicalResourceId": "NewReportTable",
            "ResourceType": "AWS::DynamoDB::Table",
        }}]
        commands = []

        def fake_aws(_cfg, *args, allow_error=False):
            commands.append(args)
            if args[:2] == ("cloudformation", "create-change-set"):
                return {"Id": approved_arn}, ""
            if args[:2] == ("cloudformation", "describe-change-set"):
                return {"Status": "CREATE_COMPLETE", "ExecutionStatus": "AVAILABLE",
                        "Changes": changes}, ""
            if args[:2] == ("cloudformation", "wait"):
                return {}, ""
            if args[:2] == ("cloudformation", "execute-change-set"):
                return {}, ""
            self.fail("Unexpected AWS call: " + "/".join(args[:2]))

        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory) / ".local"
            private.mkdir()
            output = io.StringIO()
            with (patch.object(install, "LOCAL", private),
                  patch.object(install, "revision", return_value="a" * 40),
                  patch.object(install, "verify_account"),
                  patch.object(install, "read_stack", return_value=None),
                  patch.object(install, "resolved_parameters",
                               return_value=({"NotificationEmail": "alerts@fake.tld"}, "")),
                  patch.object(install, "aws_run", side_effect=fake_aws),
                  contextlib.redirect_stdout(output)):
                install.plan(cfg, "ingestion")
                self.assertTrue((private / "plans" / "ingestion.json").exists())
                self.assertNotIn("alerts@fake.tld", output.getvalue())
                self.assertFalse(any(c[:2] == ("cloudformation", "execute-change-set")
                                     for c in commands))
                with self.assertRaises(install.InstallError):
                    install.apply(cfg, "ingestion", "arn:other", False)
                self.assertFalse(any(c[:2] == ("cloudformation", "execute-change-set")
                                     for c in commands))
                install.apply(cfg, "ingestion", approved_arn, False)
                self.assertTrue(any(c[:2] == ("cloudformation", "execute-change-set")
                                    for c in commands))
                self.assertFalse((private / "plans" / "ingestion.json").exists())
                self.assertFalse(list(private.glob(".params-*")))

    def test_public_edge_requires_extra_consent_before_aws_calls(self):
        with self.assertRaises(install.InstallError):
            install.apply(configured(), "edge", "arn:approved", False)

    def test_release_keys_include_pinned_commit_and_content_digest(self):
        commit = "a" * 40
        checksum = "b" * 64
        self.assertEqual(
            install.artifact_key(commit, "web", checksum),
            "releases/" + commit + "/web/" + checksum + "/bootstrap.zip",
        )


if __name__ == "__main__":
    unittest.main()
