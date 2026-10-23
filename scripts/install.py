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


def main() -> None:
    parser = argparse.ArgumentParser(description="Locally configured DMARC Tally installer")
    parser.add_argument("command", choices=["init", "check", "build", "upload", "plan", "apply"])
    parser.add_argument("component", nargs="?", choices=sorted(STACKS))
    parser.add_argument("--approve", help="Exact reviewed CloudFormation change-set ARN")
    parser.add_argument("--allow-public-edge", action="store_true",
                        help="Explicitly approve creating or updating the public HTTPS API")
    args = parser.parse_args()
    if args.command == "init":
        init()
        return
    cfg = load_config()
    if args.command == "check":
        print("Ignored local configuration is valid. No AWS calls were made.")
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
