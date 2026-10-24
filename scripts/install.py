#!/usr/bin/env python3
"""DMARC Tally installation CLI. Public code; concrete settings stay in .local/.

Only the 'plan' command creates a non-executable CloudFormation change set.
Only 'apply' with the exact reviewed ARN can execute one. No DNS operations.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from zipfile import BadZipFile, ZipFile
from io import BytesIO

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / ".local"
CONFIG = LOCAL / "production.json"
EXAMPLE = ROOT / "config" / "production.example.json"
MANIFEST = LOCAL / "release.json"
BOOTSTRAP_ORIGIN = "https://bootstrap.invalid"  # Until the managed HTTP API exists.
STACKS = {
    "artifacts": "production-artifacts.yaml",
    "ingestion": "production-ingestion.yaml",
    "web": "web-private.yaml",
    "edge": "web-http-edge.yaml",
    "receiving": "ses-receiving.yaml",
}

class InstallError(Exception):
    """Intentionally contains no email, token, AWS response or config content."""


def require(valid: bool, field: str) -> None:
    if not valid:
        raise InstallError("Invalid or missing installation setting: " + field)


def text_field(value: object, field: str) -> str:
    require(isinstance(value, str) and bool(value) and value == value.strip()
            and not any(ch.isspace() for ch in value), field)
    return value  # type: ignore[return-value]


def valid_domain(value: object, field: str) -> str:
    domain = text_field(value, field).lower()
    require(len(domain) <= 253 and "." in domain, field)
    require(all(0 < len(part) <= 63
                and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", part)
                for part in domain.split(".")), field)
    require(not domain.endswith((".invalid", ".example", ".test"))
            and domain not in {"example.com", "example.net", "example.org"}, field)
    return domain


def valid_email(value: object, field: str) -> str:
    email = text_field(value, field)
    require(len(email) <= 254 and re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+", email) is not None, field)
    valid_domain(email.split("@", 1)[1], field)
    return email


def validate_config(cfg: object) -> dict:
    require(isinstance(cfg, dict), "configuration file")
    require(isinstance(cfg.get("aws"), dict), "aws")
    require(isinstance(cfg.get("email"), dict), "email")
    aws = cfg["aws"]
    email = cfg["email"]
    require(re.fullmatch(r"\d{12}", str(aws.get("account_id", ""))) is not None
            and aws["account_id"] != "000000000000", "aws.account_id")
    profile = text_field(aws.get("profile"), "aws.profile")
    require(re.fullmatch(r"[A-Za-z0-9_.-]+", profile) is not None
            and "CHANGE_ME" not in profile, "aws.profile")
    region = text_field(aws.get("region"), "aws.region")
    require(re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d+", region) is not None, "aws.region")
    prefix = text_field(cfg.get("stack_prefix"), "stack_prefix")
    require(len(prefix) <= 96 and re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", prefix)
            is not None, "stack_prefix")
    domains = cfg.get("monitored_domains")
    require(isinstance(domains, list) and 1 <= len(domains) <= 30, "monitored_domains")
    normalized = [valid_domain(domain, "monitored_domains") for domain in domains]
    require(len(set(normalized)) == len(normalized), "monitored_domains")
    for name in ("administrator", "alerts", "sender", "receiving"):
        valid_email(email.get(name), "email." + name)
    identity = text_field(email.get("sender_identity"), "email.sender_identity")
    if "@" in identity:
        valid_email(identity, "email.sender_identity")
    else:
        valid_domain(identity, "email.sender_identity")
    rule_set = text_field(email.get("receipt_rule_set"), "email.receipt_rule_set")
    require(re.fullmatch(r"[A-Za-z0-9_-]{1,64}", rule_set) is not None
            and "CHANGE_ME" not in rule_set, "email.receipt_rule_set")
    rule_name = text_field(email.get("receipt_rule_name"), "email.receipt_rule_name")
    require(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{1,62}[A-Za-z0-9])", rule_name)
            is not None, "email.receipt_rule_name")
    return cfg


def load_config() -> dict:
    if CONFIG.is_symlink():
        raise InstallError("Local installation configuration must be a regular file.")
    try:
        cfg = json.loads(CONFIG.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise InstallError("Copy and configure .local/production.json first.") from error
    return validate_config(cfg)


def save_private(path: Path, value: dict) -> None:
    LOCAL.mkdir(mode=0o700, exist_ok=True)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink():
        raise InstallError("Refusing to replace a symlink inside .local.")
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, prefix=".write-",
        delete=False,
    ) as temporary:
        temporary_path = Path(temporary.name)
        os.chmod(temporary_path, 0o600)
        json.dump(value, temporary, indent=2, sort_keys=True)
        temporary.write("\n")
    os.replace(temporary_path, path)


def init() -> None:
    LOCAL.mkdir(mode=0o700, exist_ok=True)
    if CONFIG.exists() or CONFIG.is_symlink():
        raise InstallError(".local/production.json already exists; not overwriting it.")
    with CONFIG.open("x", encoding="utf-8") as destination:
        os.chmod(CONFIG, 0o600)
        destination.write(EXAMPLE.read_text(encoding="utf-8"))
    print("Created ignored .local/production.json; replace every example value.")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fingerprint(value: object) -> str:
    return sha256_bytes(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def revision() -> str:
    def git(*args: str) -> str:
        result = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)
        if result.returncode:
            raise InstallError("Git checkout is required for a pinned release.")
        return result.stdout.strip()

    sha = git("rev-parse", "HEAD")
    require(re.fullmatch(r"[0-9a-f]{40}", sha) is not None, "release commit")
    if git("status", "--porcelain", "--untracked-files=normal"):
        raise InstallError("Tracked checkout must be clean before release/install actions.")
    return sha


def verify_bootstrap_zip(content: bytes) -> None:
    try:
        with ZipFile(BytesIO(content)) as archive:
            if set(archive.namelist()) != {"bootstrap"}:
                raise InstallError("Release ZIP must contain only the root bootstrap.")
            member = archive.getinfo("bootstrap")
            binary = archive.read(member)
            if not (binary.startswith(b"\x7fELF") and len(binary) >= 20
                    and binary[4] == 2 and int.from_bytes(binary[18:20], "little") == 62
                    and ((member.external_attr >> 16) & 0o111)):
                raise InstallError("Release ZIP needs an executable Linux x86-64 bootstrap.")
    except (BadZipFile, OSError, RuntimeError, ValueError) as error:
        raise InstallError("Invalid packaged Lambda bootstrap ZIP.") from error


def artifact_key(commit: str, binary: str, digest: str) -> str:
    require(re.fullmatch(r"[a-f0-9]{40}", commit) is not None, "release commit")
    require(binary in ("ingest", "web"), "release binary")
    require(re.fullmatch(r"[a-f0-9]{64}", digest) is not None, "release checksum")
    return f"releases/{commit}/{binary}/{digest}/bootstrap.zip"


def build() -> None:
    sha = revision()
    artifacts = {}
    for binary in ("ingest", "web"):
        command = [
            "cargo", "lambda", "build", "--release", "--locked",
            "--package", "tally-lambda", "--bin", binary,
            "--output-format", "zip", "--target", "x86_64-unknown-linux-gnu",
        ]
        # Builds use source only, no customer configuration or AWS credentials.
        if subprocess.run(command, cwd=ROOT, check=False).returncode:
            raise InstallError("Local Lambda build failed: " + binary)
        source = ROOT / "target" / "lambda" / binary / "bootstrap.zip"
        try:
            data = source.read_bytes()
        except OSError as error:
            raise InstallError("Missing packaged ZIP: " + binary) from error
        verify_bootstrap_zip(data)
        digest = sha256_bytes(data)
        dest = LOCAL / "build" / sha / (binary + ".zip")
        dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        dest.write_bytes(data)
        os.chmod(dest, 0o600)
        artifacts[binary] = {
            "file": str(dest.relative_to(ROOT)),
            "sha256": digest,
            "key": artifact_key(sha, binary, digest),
        }
    save_private(MANIFEST, {"commit": sha, "artifacts": artifacts})
    print("Built and checked x86-64 Lambda ZIPs from pinned commit " + sha)
    print("Checksum manifest saved under ignored .local/release.json.")


def load_release() -> tuple[dict, dict]:
    sha = revision()
    try:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        require(manifest.get("commit") == sha, "release commit (rebuild after checkout change)")
        artifacts = manifest["artifacts"]
        for binary in ("ingest", "web"):
            entry = artifacts[binary]
            path = (ROOT / entry["file"]).resolve()
            require(path.is_relative_to(LOCAL.resolve()) and path.is_file()
                    and not path.is_symlink(), "release artifact path")
            raw = path.read_bytes()
            verify_bootstrap_zip(raw)
            digest = sha256_bytes(raw)
            require(digest == entry["sha256"], "release artifact SHA-256")
            require(entry["key"] == artifact_key(sha, binary, digest),
                    "versioned artifact key")
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise InstallError("Run build to create verified .local/release.json.") from error
    return manifest, artifacts


def aws_run(cfg: dict, *args: str, allow_error: bool = False) -> tuple[dict, str]:
    command = [
        "aws", "--region", cfg["aws"]["region"], "--profile", cfg["aws"]["profile"],
        *args, "--output", "json",
    ]
    try:
        is_wait = len(args) >= 2 and args[:2] == ("cloudformation", "wait")
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=1800 if is_wait else 180)
    except OSError as error:
        raise InstallError("AWS CLI is required and must be configured locally.") from error
    except subprocess.TimeoutExpired as error:
        raise InstallError("AWS operation timed out; inspect stack status before retrying.") from error
    if result.returncode:
        if allow_error:
            return {}, result.stderr
        # Never echo AWS's raw response: it may contain personal parameters.
        raise InstallError("AWS operation failed: " + args[0] + "/" + args[1])
    try:
        return (json.loads(result.stdout) if result.stdout.strip() else {}), ""
    except json.JSONDecodeError as error:
        raise InstallError("Invalid AWS CLI JSON response.") from error


def verify_account(cfg: dict) -> None:
    info, _ = aws_run(cfg, "sts", "get-caller-identity")
    if info.get("Account") != cfg["aws"]["account_id"]:
        raise InstallError("Configured AWS account differs from active AWS CLI credentials.")


def stack_name(cfg: dict, component: str) -> str:
    require(component in STACKS, "stack component")
    return cfg["stack_prefix"] + "-" + component


def read_stack(cfg: dict, component: str, optional: bool = False) -> dict | None:
    result, stderr = aws_run(
        cfg, "cloudformation", "describe-stacks", "--stack-name", stack_name(cfg, component),
        allow_error=True,
    )
    if stderr:
        if optional and "does not exist" in stderr:
            return None
        raise InstallError("Could not read prerequisite stack: " + component)
    stacks = result.get("Stacks") or []
    if len(stacks) != 1 or stacks[0].get("StackName") != stack_name(cfg, component):
        raise InstallError("Unexpected CloudFormation stack result: " + component)
    if optional and stacks[0]["StackStatus"] == "REVIEW_IN_PROGRESS":
        # A not-yet-executed CREATE change set has no provisioned resources.
        return None
    if stacks[0]["StackStatus"] not in ("CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"):
        raise InstallError("Stack not in a deployable state: " + component)
    return stacks[0]


def outputs_for(cfg: dict, component: str, optional: bool = False) -> dict:
    stack = read_stack(cfg, component, optional=optional)
    if stack is None:
        return {}
    return {item["OutputKey"]: item["OutputValue"] for item in stack.get("Outputs", [])}


def parameters(component: str, cfg: dict, outputs: dict, release: dict) -> dict:
    email = cfg["email"]
    domains = ",".join(cfg["monitored_domains"])
    if component == "artifacts":
        return {}
    if component == "ingestion":
        return {
            "CodeBucket": outputs["artifacts"]["ArtifactBucket"],
            "CodeKey": release["ingest"]["key"],
            "MonitoredDomains": domains, "NotificationEmail": email["alerts"],
        }
    if component == "web":
        return {
            "CodeBucket": outputs["artifacts"]["ArtifactBucket"],
            "CodeKey": release["web"]["key"],
            "ReportsTableName": outputs["ingestion"]["ReportsTable"],
            "MonitoredDomains": domains, "AdministratorEmail": email["administrator"],
            "ReceivingAddress": email["receiving"],
            "ReceiptRuleSetName": email["receipt_rule_set"],
            "ReceiptRuleName": email["receipt_rule_name"],
            "IntakeBucketName": outputs["ingestion"]["IntakeBucket"],
            "FailureAlertTopicArn": outputs["ingestion"]["FailureAlertTopicArn"],
            "FailureAlarmNames": outputs["ingestion"]["FailureAlarmNames"],
            "FailureNotificationEmail": email["alerts"],
            "IngestionStackName": stack_name(cfg, "ingestion"),
            "SenderEmail": email["sender"], "VerifiedSenderIdentity": email["sender_identity"],
            "PublicOrigin": outputs.get("edge", {}).get("WebHttpsOrigin", BOOTSTRAP_ORIGIN),
        }
    if component == "edge":
        return {"WebFunctionArn": outputs["web"]["WebFunctionArn"]}
    if component == "receiving":
        return {
            "ReceiptRuleSetName": email["receipt_rule_set"],
            "ReceiptRuleName": email["receipt_rule_name"],
            "ReceivingAddress": email["receiving"],
            "IntakeBucketName": outputs["ingestion"]["IntakeBucket"],
            "EnableReceiving": "false",  # Used only on CREATE; UPDATE retains deployed state.
        }
    raise InstallError("Unknown CloudFormation component.")


def change_set_parameters(component: str, params: dict, change_type: str) -> list[dict]:
    """Preserve manually activated SES receiving on updates; never activate it here."""
    require(change_type in ("CREATE", "UPDATE"), "change-set type")
    if component == "receiving":
        require(params.get("EnableReceiving") == "false", "receiving activation")
    result = []
    for key, value in params.items():
        if component == "receiving" and key == "EnableReceiving" and change_type == "UPDATE":
            result.append({"ParameterKey": key, "UsePreviousValue": True})
        else:
            result.append({"ParameterKey": key, "ParameterValue": value})
    return result


def dependencies(component: str) -> tuple[str, ...]:
    return {
        "artifacts": (), "ingestion": ("artifacts",),
        "web": ("artifacts", "ingestion"), "edge": ("web",),
        "receiving": ("ingestion",),
    }[component]


def verified_object(cfg: dict, bucket: str, entry: dict) -> None:
    info, _ = aws_run(cfg, "s3api", "head-object", "--bucket", bucket,
                      "--key", entry["key"], "--checksum-mode", "ENABLED")
    if (info.get("Metadata", {}).get("sha256") != entry["sha256"]
            or info.get("ChecksumSHA256") !=
            base64.b64encode(bytes.fromhex(entry["sha256"])).decode("ascii")):
        raise InstallError("Uploaded Lambda release checksum does not match local manifest.")


def upload(cfg: dict) -> None:
    verify_account(cfg)
    _, artifacts = load_release()
    bucket = outputs_for(cfg, "artifacts").get("ArtifactBucket")
    require(bool(bucket), "production artifacts stack output")
    for binary in ("ingest", "web"):
        entry = artifacts[binary]
        data = (ROOT / entry["file"]).read_bytes()
        checksum = base64.b64encode(bytes.fromhex(entry["sha256"])).decode("ascii")
        _, error = aws_run(
            cfg, "s3api", "put-object", "--bucket", bucket, "--key", entry["key"],
            "--body", str(ROOT / entry["file"]), "--checksum-sha256", checksum,
            "--metadata", "sha256=" + entry["sha256"], "--if-none-match", "*",
            allow_error=True,
        )
        if error:
            # A same-key existing object is safe only when it has our digest.
            try:
                verified_object(cfg, bucket, entry)
            except InstallError as exc:
                raise InstallError("Could not safely upload " + binary + " Lambda ZIP.") from exc
        verified_object(cfg, bucket, entry)
        print("Verified immutable " + binary + " Lambda release in private S3 bucket.")


def resolved_parameters(cfg: dict, component: str) -> tuple[dict, str]:
    outputs = {key: outputs_for(cfg, key) for key in dependencies(component)}
    if component == "web":
        outputs["edge"] = outputs_for(cfg, "edge", optional=True)
    manifest_hash = ""
    release = {}
    if component in ("ingestion", "web"):
        manifest, release = load_release()
        manifest_hash = fingerprint(manifest)
        verified_object(cfg, outputs["artifacts"]["ArtifactBucket"],
                        release["ingest" if component == "ingestion" else "web"])
    try:
        return parameters(component, cfg, outputs, release), manifest_hash
    except KeyError as error:
        raise InstallError("Missing prerequisite stack output for " + component) from error


def check_changes(changes: list) -> None:
    for item in changes:
        change = item.get("ResourceChange") or {}
        action = change.get("Action")
        if action not in ("Add", "Modify"):
            raise InstallError("CloudFormation change would remove/import a resource.")
        if action == "Modify" and change.get("Replacement") != "False":
            raise InstallError("CloudFormation change might replace an existing resource.")
        if (action == "Modify" and change.get("ResourceType")
                in ("AWS::S3::Bucket", "AWS::DynamoDB::Table")):
            raise InstallError("Changes to durable data resources need a separate manual review.")


def changes_digest(changes: list) -> str:
    return fingerprint(changes)


def print_changes(changes: list) -> None:
    for item in changes:
        change = item.get("ResourceChange") or {}
        # Only generic resource types, logical IDs and actions; no parameter values.
        print("  " + str(change.get("Action")) + " " +
              str(change.get("ResourceType")) + " / " +
              str(change.get("LogicalResourceId")))


def local_plan_path(component: str) -> Path:
    return LOCAL / "plans" / (component + ".json")


def plan(cfg: dict, component: str) -> None:
    require(component in STACKS, "stack component")
    commit = revision()
    verify_account(cfg)
    params, manifest_hash = resolved_parameters(cfg, component)
    existing = read_stack(cfg, component, optional=True)
    change_type = "UPDATE" if existing else "CREATE"
    change_params = change_set_parameters(component, params, change_type)
    template = ROOT / "infra" / STACKS[component]
    change_name = "manual-" + os.urandom(6).hex()
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=LOCAL,
        prefix=".params-", suffix=".json", delete=False,
    ) as tmp:
        parameters_path = Path(tmp.name)
        os.chmod(parameters_path, 0o600)
        json.dump(change_params, tmp)
    try:
        response, _ = aws_run(
            cfg, "cloudformation", "create-change-set",
            "--stack-name", stack_name(cfg, component),
            "--change-set-name", change_name, "--change-set-type", change_type,
            "--template-body", "file://" + str(template),
            "--parameters", "file://" + str(parameters_path),
            "--capabilities", "CAPABILITY_IAM",
        )
    finally:
        parameters_path.unlink(missing_ok=True)
    arn = response.get("Id")
    require(isinstance(arn, str) and arn.startswith("arn:"), "change-set reference")
    # CloudFormation returns FAILED when an UPDATE contains no changes.
    aws_run(cfg, "cloudformation", "wait", "change-set-create-complete",
            "--change-set-name", arn, "--stack-name", stack_name(cfg, component),
            allow_error=True)
    review, _ = aws_run(cfg, "cloudformation", "describe-change-set",
                        "--change-set-name", arn, "--stack-name", stack_name(cfg, component))
    if review.get("Status") == "FAILED":
        if "didn't contain changes" in review.get("StatusReason", ""):
            print("No CloudFormation changes needed for " + component + ".")
            return
        raise InstallError("CloudFormation could not prepare this change set.")
    if review.get("Status") != "CREATE_COMPLETE":
        raise InstallError("CloudFormation change set is not ready to review.")
    changes = review.get("Changes") or []
    print("Proposed " + change_type + " for " + component + " (no private values displayed):")
    print_changes(changes)
    check_changes(changes)
    save_private(local_plan_path(component), {
        "component": component, "change_set": arn, "change_type": change_type,
        "commit": commit, "config_hash": fingerprint(cfg),
        "manifest_hash": manifest_hash, "template_hash": sha256_bytes(template.read_bytes()),
        "parameters_hash": fingerprint(change_params), "changes_hash": changes_digest(changes),
    })
    print("Change set is prepared but NOT executed.")
    print("To approve it, run: python3 scripts/install.py apply " + component +
          " --approve " + arn +
          (" --allow-public-edge" if component == "edge" else ""))


def apply(cfg: dict, component: str, approved: str | None, public_edge: bool) -> None:
    require(component in STACKS, "stack component")
    if component == "edge" and not public_edge:
        raise InstallError("Public HTTPS API needs explicit --allow-public-edge approval.")
    if not approved:
        raise InstallError("Use --approve with the exact reviewed change-set ARN.")
    try:
        saved = json.loads(local_plan_path(component).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise InstallError("No locally reviewed change set exists for this component.") from error
    if saved.get("change_set") != approved or saved.get("component") != component:
        raise InstallError("Approved change-set ARN does not match local review.")
    if saved.get("commit") != revision() or saved.get("config_hash") != fingerprint(cfg):
        raise InstallError("Checkout or local installation configuration changed since review.")
    verify_account(cfg)
    params, manifest_hash = resolved_parameters(cfg, component)
    change_params = change_set_parameters(component, params, saved.get("change_type"))
    template = ROOT / "infra" / STACKS[component]
    if (saved.get("manifest_hash") != manifest_hash
            or saved.get("template_hash") != sha256_bytes(template.read_bytes())
            or saved.get("parameters_hash") != fingerprint(change_params)):
        raise InstallError("Artifact, template or resolved parameters changed since review.")
    review, _ = aws_run(cfg, "cloudformation", "describe-change-set",
                        "--change-set-name", approved, "--stack-name", stack_name(cfg, component))
    changes = review.get("Changes") or []
    if (review.get("Status") != "CREATE_COMPLETE"
            or review.get("ExecutionStatus") != "AVAILABLE"
            or saved.get("changes_hash") != changes_digest(changes)):
        raise InstallError("Reviewed change set is no longer current.")
    check_changes(changes)
    aws_run(cfg, "cloudformation", "execute-change-set",
            "--change-set-name", approved, "--stack-name", stack_name(cfg, component))
    # CloudFormation runs asynchronously; wait synchronously for completion.
    aws_run(cfg, "cloudformation", "wait", "stack-" + saved["change_type"].lower() +
            "-complete", "--stack-name", stack_name(cfg, component))
    local_plan_path(component).unlink(missing_ok=True)
    print("CloudFormation " + component + " change set completed.")



# Installation discovery deliberately has no local state of its own: it
# derives progress from CloudFormation every time it runs. Do not use these
# lightweight inspection results as permission to execute a change set.
INSTALL_ORDER = ("artifacts", "ingestion", "web", "edge", "receiving")
REQUIRED_OUTPUTS = {
    "artifacts": ("ArtifactBucket",),
    "ingestion": ("ReportsTable", "IntakeBucket", "FailureAlertTopicArn", "FailureAlarmNames"),
    "web": ("WebFunctionArn",),
    "edge": ("WebHttpsOrigin",),
    "receiving": ("ReceiptRuleName",),
}


def inspect_installation_stack(cfg: dict, component: str) -> dict:
    """Read live CloudFormation stack metadata; never modify resources."""
    try:
        result, error = aws_run(
            cfg, "cloudformation", "describe-stacks",
            "--stack-name", stack_name(cfg, component), allow_error=True,
        )
    except InstallError:
        return {"state": "unavailable", "outputs": {}, "parameters": {}}
    if error:
        if "does not exist" in error:
            return {"state": "missing", "outputs": {}, "parameters": {}}
        return {"state": "unavailable", "outputs": {}, "parameters": {}}
    stacks = result.get("Stacks")
    if (not isinstance(stacks, list) or len(stacks) != 1
            or stacks[0].get("StackName") != stack_name(cfg, component)):
        return {"state": "unavailable", "outputs": {}, "parameters": {}}
    stack = stacks[0]
    status = stack.get("StackStatus")
    if status == "REVIEW_IN_PROGRESS":
        state = "pending"
    elif status in ("CREATE_COMPLETE", "UPDATE_COMPLETE"):
        state = "deployed"
    else:
        # Rollbacks and in-progress/failed updates must not be called ready.
        state = "attention"
    outputs = {row["OutputKey"]: row["OutputValue"]
               for row in stack.get("Outputs", [])
               if isinstance(row, dict) and isinstance(row.get("OutputKey"), str)
               and isinstance(row.get("OutputValue"), str)}
    parameters = {row["ParameterKey"]: row["ParameterValue"]
                  for row in stack.get("Parameters", [])
                  if isinstance(row, dict) and isinstance(row.get("ParameterKey"), str)
                  and isinstance(row.get("ParameterValue"), str)}
    missing = (tuple(key for key in REQUIRED_OUTPUTS[component] if not outputs.get(key))
               if state == "deployed" else ())
    return {"state": state, "outputs": outputs, "parameters": parameters,
            "missing_outputs": missing}


def inspect_installation(cfg: dict) -> dict:
    """Read-only, authenticated-to-AWS inventory for status and summary."""
    verify_account(cfg)  # Refuse to inspect the wrong account.
    return {component: inspect_installation_stack(cfg, component)
            for component in INSTALL_ORDER}


def next_install_action(stacks: dict) -> str:
    """Conservative recommendation, NOT approval to change anything."""
    for component in INSTALL_ORDER:
        state = stacks[component]["state"]
        if state in ("attention", "unavailable", "pending"):
            return (f"Inspect the {component} CloudFormation stack/change set in AWS "
                    "and resolve its state before proceeding.")
        if stacks[component].get("missing_outputs"):
            return (f"Inspect/update the {component} stack: expected outputs are "
                    "missing. Do not assume the next stack can deploy yet.")

    for component in ("artifacts", "ingestion", "web", "edge"):
        if stacks[component]["state"] == "missing":
            if component == "artifacts":
                return "Plan/review/apply the artifacts stack."
            if component == "ingestion":
                return ("Build/upload verified Lambda ZIPs, then "
                        "plan/review/apply the ingestion stack.")
            if component == "web":
                return "Plan/review/apply the private web stack."
            return "Plan/review/apply the HTTPS edge stack with explicit public-edge consent."

    edge_origin = stacks["edge"]["outputs"].get("WebHttpsOrigin")
    web_origin = stacks["web"]["parameters"].get("PublicOrigin")
    if not edge_origin or web_origin != edge_origin:
        return ("Plan/review/apply the web stack again using the deployed "
                "HTTPS edge origin; sign-in is not ready yet.")

    if stacks["receiving"]["state"] == "missing":
        return ("Verify SES identity/rule-set safety, then plan/review/apply "
                "the receiving stack disabled. Test sign-in first.")
    state = stacks["receiving"]["parameters"].get("EnableReceiving")
    if state != "true":
        return ("Review the dedicated MX, SES rule order and destination; "
                "enable receiving only by a separate approved operation, "
                "then test delivery before editing monitored-domain rua.")
    return ("Verify controlled SES-to-S3-to-DynamoDB delivery and real alarm "
            "email receipt; only then redirect monitored-domain rua.")


def show_status(cfg: dict, stacks: dict) -> None:
    """Avoid printing account-specific email/receiving addresses here."""
    print("DMARC Tally installation status (read-only CloudFormation snapshot)")
    print("AWS account: checked; region: " + cfg["aws"]["region"])
    for component in INSTALL_ORDER:
        info = stacks[component]
        state = info["state"]
        label = {
            "missing": "Not deployed",
            "pending": "Change set prepared; not deployed",
            "deployed": "Stack deployed",
            "attention": "Needs CloudFormation review",
            "unavailable": "Unable to inspect",
        }[state]
        if state == "deployed" and info.get("missing_outputs"):
            label = "Deployed, but expected outputs are missing"
        if component == "receiving" and state == "deployed":
            enable = info["parameters"].get("EnableReceiving")
            if enable == "true":
                label += " (rule enabled; delivery unverified)"
            elif enable == "false":
                label += " (rule disabled)"
            else:
                label += " (rule enablement unverified)"
        print(f"  {component}: {label}")
    print("Next action: " + next_install_action(stacks))
    print("This does not verify SES sender/sandbox, DNS, login, report flow or alert delivery.")


def selected_release(stacks: dict) -> str:
    """Identify a local build and whether deployed Lambda CodeKeys match it."""
    if MANIFEST.is_symlink():
        return "Not confirmed (release manifest is a symlink)"
    try:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        commit = manifest.get("commit")
        if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
            return "Not confirmed (no valid local release manifest)"
        artifacts = manifest["artifacts"]
        keys = {name: artifacts[name]["key"] for name in ("ingest", "web")}
        if not all(isinstance(keys[name], str) and
                   keys[name].startswith("releases/" + commit + "/")
                   for name in keys):
            return "Not confirmed (release manifest is inconsistent)"
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return "Not confirmed (no valid local release manifest)"
    deployed = (stacks["ingestion"]["parameters"].get("CodeKey") == keys["ingest"]
                and stacks["web"]["parameters"].get("CodeKey") == keys["web"])
    return (commit[:12] + (" (both deployed Lambda CodeKeys match the local manifest)"
                           if deployed else
                           " (local build; deployed Lambda versions not confirmed)"))


def show_summary(cfg: dict, stacks: dict) -> None:
    """Explicitly requested *private* output for the local administrator."""
    email = cfg["email"]
    origin = stacks["edge"]["outputs"].get("WebHttpsOrigin")
    # Never echo arbitrary stack output as a URL unless it is a plain HTTPS
    # origin. The corresponding web Lambda origin may still be unreconciled.
    if not isinstance(origin, str) or not re.fullmatch(
            r"https://[a-zA-Z0-9.-]+(?::[0-9]{1,5})?/?", origin):
        origin = "Not deployed / not confirmed"
    print("PRIVATE installation summary — do not paste into public logs or issues")
    print("Dashboard URL: " + origin)
    print("Administrator sign-in: " + email["administrator"])
    print("DMARC receiving/forwarding address: " + email["receiving"])
    print("Login email sender: " + email["sender"])
    print("Failure alert email: " + email["alerts"])
    print("Monitored domains: " + ", ".join(cfg["monitored_domains"]))
    print("Selected release: " + selected_release(stacks))
    print("Next action: " + next_install_action(stacks))
    print("Configuration and stack outputs are not proof of successful mail or alarm delivery.")



# Read-only pre-login checks use the existing AWS CLI adapter and never
# change deployed resources. Each diagnostic has an explicit next step.
def preflight_result(name: str, state: str, action: str) -> tuple[str, str, str]:
    return name, state, action


def probe_aws(cfg: dict, service: str, operation: str, *args: str) -> dict | None:
    """Bounded read-only AWS lookup, never exposing CLI stderr or responses."""
    try:
        data, error = aws_run(
            cfg, service, operation, *args,
            "--cli-connect-timeout", "5", "--cli-read-timeout", "10",
            allow_error=True,
        )
    except InstallError:
        return None
    return data if not error and isinstance(data, dict) else None


def preflight_tools() -> list[tuple[str, str, str]]:
    """Current install method is a local source build (no release bundles)."""
    checks = []
    if sys.version_info < (3, 11):
        checks.append(preflight_result(
            "Python", "ACTION", "Install Python 3.11 or later."))
    else:
        checks.append(preflight_result("Python", "READY", "Python 3.11+ is available."))
    for name, executable in (("Git", "git"), ("AWS CLI", "aws"),
                             ("Rust/Cargo", "cargo"), ("Zig", "zig")):
        state = "READY" if shutil.which(executable) else "ACTION"
        checks.append(preflight_result(
            name, state,
            "Available." if state == "READY" else
            f"Install {name} for the current source-build installation method."))
    if shutil.which("aws"):
        try:
            aws_version = subprocess.run(
                ["aws", "--version"], capture_output=True, text=True,
                timeout=8, check=False,
            )
            cli_v2 = (aws_version.returncode == 0 and
                      "aws-cli/2." in (aws_version.stdout + " " + aws_version.stderr))
        except (OSError, subprocess.TimeoutExpired):
            cli_v2 = False
        if not cli_v2:
            checks.append(preflight_result(
                "AWS CLI version", "ACTION",
                "Install AWS CLI v2, which is required by this installer."))
    if shutil.which("cargo"):
        try:
            result = subprocess.run(
                ["cargo", "lambda", "--version"], capture_output=True,
                text=True, timeout=8, check=False,
            )
            available = result.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            available = False
    else:
        available = False
    checks.append(preflight_result(
        "cargo-lambda", "READY" if available else "ACTION",
        "Available." if available else
        "Install cargo-lambda before running the source-build installer."))
    return checks


def verified_ses_identity(value: dict | None) -> bool:
    return bool(value is not None and value.get("VerificationStatus") == "SUCCESS"
                and value.get("VerifiedForSendingStatus") is True)


def receives_for_rule(rule: dict, address: str) -> bool:
    """Whether a receipt rule could match the intended SMTP recipient."""
    recipients = rule.get("Recipients") or []
    if not recipients:
        return True  # A rule without recipients accepts every verified domain.
    domain = address.rsplit("@", 1)[-1]
    return any(isinstance(item, str) and
               item.lower().rstrip(".") in (address.lower(), domain.lower())
               for item in recipients)


def preflight_receiving(cfg: dict) -> list[tuple[str, str, str]]:
    """Inspect existing rule sets without activating/changing SES."""
    expected_set = cfg["email"]["receipt_rule_set"]
    expected_rule = cfg["email"]["receipt_rule_name"]
    address = cfg["email"]["receiving"]
    checks = []
    receiving_identity = probe_aws(
        cfg, "sesv2", "get-email-identity", "--email-identity",
        address.rsplit("@", 1)[-1],
    )
    if receiving_identity is None:
        checks.append(preflight_result(
            "SES receiving identity", "UNKNOWN",
            "Confirm the dedicated receiving domain is verified in SES in this region; "
            "inspect identity/read permissions if the lookup failed."))
    elif receiving_identity.get("VerificationStatus") == "SUCCESS":
        checks.append(preflight_result(
            "SES receiving identity", "READY", "Dedicated receiving identity verified."))
    else:
        checks.append(preflight_result(
            "SES receiving identity", "LATER",
            "Verify the dedicated SES receiving domain before activating intake."))

    active = probe_aws(cfg, "ses", "describe-active-receipt-rule-set")
    if active is None:
        checks.append(preflight_result(
            "Active SES receipt rules", "UNKNOWN",
            "Check SES receiving support, permissions and the active rule set in this region."))
        return checks

    active_set = (active.get("Metadata") or {}).get("Name")
    active_rules = active.get("Rules") or []
    if not isinstance(active_rules, list):
        active_rules = []
    if active_set is not None and active_set != expected_set:
        checks.append(preflight_result(
            "Active SES rule set", "ACTION",
            "A different receipt rule set is active. Review existing receivers before "
            "any activation; never replace an unrelated rule set automatically."))
    elif active_set is None:
        checks.append(preflight_result(
            "Active SES rule set", "LATER",
            "No receipt rule set is active. Review existing rules before separately "
            "approving activation."))
    else:
        checks.append(preflight_result(
            "Active SES rule set", "READY",
            "The configured receipt rule set is active; rule and delivery still need testing."))

    rules = active_rules
    if active_set != expected_set:
        target = probe_aws(
            cfg, "ses", "describe-receipt-rule-set",
            "--rule-set-name", expected_set,
        )
        if target is None:
            checks.append(preflight_result(
                "Intended SES rule set", "UNKNOWN",
                "Confirm the configured receipt rule set exists and can be described. "
                "It must exist before provisioning the disabled receiving rule."))
            return checks
        rules = target.get("Rules") or []
        if not isinstance(rules, list):
            rules = []

    match = next((rule for rule in rules
                  if isinstance(rule, dict) and rule.get("Name") == expected_rule), None)
    if match is None:
        checks.append(preflight_result(
            "Intended SES receipt rule", "LATER",
            "Create the exact-recipient rule disabled through a reviewed receiving-stack "
            "change set; do not redirect DMARC rua yet."))
    elif match.get("Recipients") != [address]:
        checks.append(preflight_result(
            "Intended SES receipt rule", "ACTION",
            "The existing rule does not match exactly the configured recipient. "
            "Review its scope before changing or enabling it."))
    else:
        checks.append(preflight_result(
            "Intended SES receipt rule", "READY" if match.get("Enabled") else "LATER",
            "Configured exact recipient is enabled; confirm S3 destination and actual mail flow."
            if match.get("Enabled") else
            "Exact-recipient rule exists but is disabled; separately approve activation "
            "only after checking DNS, rule ordering and delivery impact."))

    # Rule sets run in order. Earlier recipient-wide/domain rules may
    # intercept messages; do not declare them conflicts without inspection.
    before = active_rules if active_set != expected_set else rules[:rules.index(match)] if match in rules else rules
    if any(isinstance(rule, dict) and rule.get("Enabled") is True
           and receives_for_rule(rule, address) for rule in before):
        checks.append(preflight_result(
            "SES rule-order overlap", "ACTION",
            "An enabled earlier/active rule could also match the reporting address. "
            "Review actions and ordering before activating the intended rule."))
    else:
        checks.append(preflight_result(
            "SES rule-order overlap", "READY",
            "No enabled preceding rule matches the reporting recipient in the inspected set."))
    return checks


def run_preflight(cfg: dict) -> bool:
    """Login prerequisites determine exit code; receiving is advisory."""
    checks = preflight_tools()
    receiving_checks = []
    if not shutil.which("aws"):
        checks.append(preflight_result(
            "AWS account/region", "UNKNOWN",
            "Install/configure AWS CLI v2, then check the AWS profile and region."))
    else:
        try:
            verify_account(cfg)  # Explicitly fail closed on wrong account.
        except InstallError:
            checks.append(preflight_result(
                "AWS account/region", "ACTION",
                "Correct AWS profile/account credentials or region; do not deploy "
                "until the configured account matches STS."))
        else:
            checks.append(preflight_result(
                "AWS account/region", "READY",
                "STS identity matches the configured account in the selected region."))
            account = probe_aws(cfg, "sesv2", "get-account")
            if account is None:
                checks.append(preflight_result(
                    "SES sending access", "UNKNOWN",
                    "Check SES access/permissions in the configured region."))
            elif account.get("SendingEnabled") is False:
                checks.append(preflight_result(
                    "SES sending access", "ACTION",
                    "SES sending is disabled in this region. Resolve the account restriction."))
            elif account.get("SendingEnabled") is True:
                checks.append(preflight_result(
                    "SES sending access", "READY",
                    "SES sending is enabled for this region."))
            else:
                checks.append(preflight_result(
                    "SES sending access", "UNKNOWN",
                    "SES did not return an explicit sending-enabled status."))

            sender = probe_aws(
                cfg, "sesv2", "get-email-identity", "--email-identity",
                cfg["email"]["sender_identity"],
            )
            checks.append(preflight_result(
                "SES sender identity",
                "READY" if verified_ses_identity(sender)
                else "UNKNOWN" if sender is None else "ACTION",
                "Configured sending identity is verified."
                if verified_ses_identity(sender) else
                "Verify the configured sending identity in this SES region; "
                "check identity permissions if the lookup was unavailable."))

            if account is not None and account.get("ProductionAccessEnabled") is False:
                admin = cfg["email"]["administrator"]
                exact = probe_aws(
                    cfg, "sesv2", "get-email-identity", "--email-identity", admin,
                )
                parent = None if verified_ses_identity(exact) else probe_aws(
                    cfg, "sesv2", "get-email-identity", "--email-identity",
                    admin.rsplit("@", 1)[-1],
                )
                verified = verified_ses_identity(exact) or verified_ses_identity(parent)
                checks.append(preflight_result(
                    "SES sandbox administrator recipient",
                    "READY" if verified else "ACTION",
                    "SES is in the sandbox, but a verified identity covers the administrator."
                    if verified else
                    "SES is in the sandbox. Verify the administrator recipient or its SES "
                    "domain identity, or request production access before first login."))
            elif account is not None and account.get("ProductionAccessEnabled") is True:
                checks.append(preflight_result(
                    "SES sandbox administrator recipient", "READY",
                    "SES production sending access is enabled for this region."))
            else:
                checks.append(preflight_result(
                    "SES sandbox administrator recipient", "UNKNOWN",
                    "Confirm whether SES is in sandbox mode and whether the "
                    "administrator recipient needs verification."))

            receiving_checks = preflight_receiving(cfg)
            checks.extend(receiving_checks)

    print("DMARC Tally pre-login preflight (read-only; no email sent)")
    print("Region: " + cfg["aws"]["region"])
    for name, state, action in checks:
        print(f"  [{state}] {name}: {action}")
    login_checks = checks[:-len(receiving_checks)] if receiving_checks else checks
    login_issue = any(state in ("ACTION", "UNKNOWN") for _, state, _ in login_checks)
    receiving_issue = any(state in ("ACTION", "UNKNOWN")
                          for _, state, _ in receiving_checks)
    print("First login: " + (
        "Action or manual verification required." if login_issue
        else "No detected blockers for the initial login; test real delivery."
    ))
    print("Receiving: " + (
        "Manual review required before activation." if receiving_issue
        else "Follow remaining setup steps before activation/rua changes."
    ))
    print("Preflight does not modify SES, DNS or AWS, or prove mail delivery.")
    return not login_issue



def confirm_delivery(cfg: dict, key: str | None, approve: bool) -> None:
    """Explicit, operator-reviewed attestation; never invoked by plan/apply."""
    if not approve:
        raise InstallError("Use --confirm-observed-delivery after independently verifying the SES test.")
    if (not isinstance(key, str)
            or re.fullmatch(r"incoming/[A-Za-z0-9_-]{20,100}", key) is None):
        raise InstallError("Provide the exact validated incoming/<SES-message-id> S3 key.")
    verify_account(cfg)
    bucket = outputs_for(cfg, "ingestion").get("IntakeBucket")
    require(bool(bucket), "production intake bucket")
    # This checks processing of one specific object, not the provenance
    # of the S3 PUT. Operator must independently confirm SES delivery.
    observed, _ = aws_run(cfg, "s3api", "head-object",
                          "--bucket", bucket, "--key", key)
    tags, _ = aws_run(cfg, "s3api", "get-object-tagging",
                      "--bucket", bucket, "--key", key)
    if not any(t.get("Key") == "captured" and t.get("Value") == "true"
               for t in tags.get("TagSet", [])):
        raise InstallError("Selected object is not captured; verify DMARC processing first.")
    last_modified = observed.get("LastModified")
    if not isinstance(last_modified, str):
        raise InstallError("Could not verify the captured object's modification time.")
    from datetime import datetime, timezone
    try:
        observed_at = int(datetime.fromisoformat(
            last_modified.replace("Z", "+00:00")).timestamp())
    except ValueError as exc:
        raise InstallError("Could not parse S3 object observation time.") from exc
    now = int(datetime.now(timezone.utc).timestamp())
    if observed_at <= 0 or observed_at > now + 300 or now - observed_at > 7 * 86400:
        raise InstallError("Use a recent captured report from the controlled delivery test.")

    rule, _ = aws_run(cfg, "ses", "describe-active-receipt-rule-set")
    active = (rule.get("Metadata") or {}).get("Name")
    expected = cfg["email"]["receipt_rule_set"]
    address = cfg["email"]["receiving"]
    matching = [r for r in rule.get("Rules", [])
                if r.get("Name") == cfg["email"]["receipt_rule_name"]]
    if active != expected or len(matching) != 1:
        raise InstallError("Expected SES receipt rule is not active.")
    match = matching[0]
    actions = match.get("Actions") or []
    if (match.get("Enabled") is not True
            or match.get("Recipients") != [address]
            or len(actions) != 1
            or (actions[0].get("S3Action") or {}).get("BucketName") != bucket
            or (actions[0].get("S3Action") or {}).get("ObjectKeyPrefix") != "incoming/"):
        raise InstallError("Active SES rule or S3 destination does not match the intended delivery.")

    # No raw message, recipient or object key appears in retained evidence.
    evidence = {"version": 1, "observed_at": observed_at, "verified_at": now}
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8",
                                     dir=LOCAL, prefix=".delivery-", delete=False) as tmp:
        private_path = Path(tmp.name)
        os.chmod(private_path, 0o600)
        json.dump(evidence, tmp)
    try:
        aws_run(cfg, "s3api", "put-object",
                "--bucket", bucket, "--key", "setup/end-to-end-confirmed.json",
                "--body", str(private_path), "--content-type", "application/json",
                "--server-side-encryption", "AES256")
    finally:
        private_path.unlink(missing_ok=True)
    print("Recorded private operator-confirmed delivery test. Refresh /setup after deploying the updated web Lambda.")
    print("This does not independently prove S3 PUT provenance or change monitored-domain rua.")

def main() -> None:
    parser = argparse.ArgumentParser(description="Locally configured DMARC Tally installer")
    parser.add_argument("command", choices=["init", "check", "preflight", "status", "summary", "confirm-delivery", "build", "upload", "plan", "apply"])
    parser.add_argument("component", nargs="?", choices=sorted(STACKS))
    parser.add_argument("--approve", help="Exact reviewed CloudFormation change-set ARN")
    parser.add_argument("--object-key", help="Exact controlled-test S3 incoming/ key; private")
    parser.add_argument("--confirm-observed-delivery", action="store_true",
                        help="Explicit operator confirmation of SES delivery provenance")
    parser.add_argument("--allow-public-edge", action="store_true",
                        help="Explicitly approve creating or updating the public HTTPS API")
    args = parser.parse_args()
    if args.command == "init":
        init()
        return
    cfg = load_config()
    if args.command == "check":
        print("Ignored local configuration is valid. No AWS calls were made.")
    elif args.command == "preflight":
        if not run_preflight(cfg):
            sys.exit(1)
    elif args.command == "status":
        show_status(cfg, inspect_installation(cfg))
    elif args.command == "summary":
        show_summary(cfg, inspect_installation(cfg))
    elif args.command == "confirm-delivery":
        confirm_delivery(cfg, args.object_key, args.confirm_observed_delivery)
    elif args.command == "build":
        build()
    elif args.command == "upload":
        upload(cfg)
    elif args.command == "plan":
        if not args.component:
            parser.error("plan needs a stack component")
        plan(cfg, args.component)
    elif args.command == "apply":
        if not args.component:
            parser.error("apply needs a stack component")
        apply(cfg, args.component, args.approve, args.allow_public_edge)


if __name__ == "__main__":
    try:
        main()
    except (InstallError, KeyError, ValueError, TypeError) as error:
        # Never display input or any raw AWS CLI response on failure.
        if isinstance(error, InstallError):
            print("Error: " + str(error), file=sys.stderr)
        else:
            print("Error: invalid installer configuration or manifest.", file=sys.stderr)
        sys.exit(1)
