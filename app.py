from flask import Flask, request, jsonify
import re

app = Flask(__name__)

SHA40 = re.compile(r"^[0-9a-f]{40}$")


@app.route("/release-gate", methods=["POST"])
def release_gate():
    data = request.get_json(force=True)

    target = data.get("target")
    event = data.get("event")
    ref = data.get("ref")

    workflow = data.get("workflow", {})
    permissions = workflow.get("permissions", {})
    tests_passed = workflow.get("testsPassed")
    matrix_complete = workflow.get("matrixComplete")
    fail_fast = workflow.get("failFast")
    actions = workflow.get("actions", [])

    image = data.get("image", {})
    multi_stage = image.get("multiStage")
    runs_as_root = image.get("runsAsRoot")
    secret_mode = image.get("secretMode")
    critical_vulnerabilities = image.get("criticalVulnerabilities")
    digest_pinned = image.get("digestPinned")

    violations = []

    # 1. Permissions must be EXACTLY least privilege
    expected_permissions = {
        "contents": "read",
        "packages": "write",
        "id-token": "none"
    }

    if permissions != expected_permissions:
        violations.append("EXCESS_PERMISSION")

    # 2. Pull request must use pull_request, not pull_request_target
    if event == "pull_request" and workflow.get("trigger") != "pull_request":
        violations.append("UNSAFE_PR_TRIGGER")

    # 3. Tests must pass, matrix must be complete, failFast must be false
    if (
        tests_passed is not True
        or matrix_complete is not True
        or fail_fast is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # 4. Action pinning
    for action in actions:
        owner = action.get("owner")
        action_ref = action.get("ref", "")

        # actions/* may use version tags
        if owner == "actions":
            continue

        # Every third-party action requires a full lowercase SHA
        if not SHA40.fullmatch(action_ref):
            violations.append("MUTABLE_ACTION")
            break

    # 5. Image must be multi-stage
    if multi_stage is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    # 6. Container must run as non-root
    if runs_as_root is not False:
        violations.append("ROOT_RUNTIME")

    # 7. Only none or buildkit secrets are allowed
    if secret_mode not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    # 8. No critical vulnerabilities
    if critical_vulnerabilities != 0:
        violations.append("CRITICAL_CVE")

    # 9. Image must be digest pinned
    if digest_pinned is not True:
        violations.append("UNPINNED_IMAGE")

    # 10. Production must be a push to main
    if target == "production":
        if event != "push" or ref != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")

        # Production requires approval
        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    decision = "promote" if not violations else "block"

    return jsonify({
        "decision": decision,
        "violations": violations
    })





ASSIGNED_TENANT = "tenant-74pxhxr"
ALLOWED_EMAIL_DOMAIN = "notify-2vpfaru.example"


def exact_keys(obj, required_keys):
    return (
        isinstance(obj, dict)
        and set(obj.keys()) == set(required_keys)
    )


def valid_html(html):
    if not isinstance(html, str):
        return False

    # Block <script> elements
    if re.search(r"<\s*script\b", html, re.IGNORECASE):
        return False

    # Block <iframe> elements
    if re.search(r"<\s*iframe\b", html, re.IGNORECASE):
        return False

    # Block inline event handlers such as onclick=, onload=, onerror=, etc.
    if re.search(r"\bon[a-zA-Z]+\s*=", html, re.IGNORECASE):
        return False

    # Block javascript: URLs
    if re.search(r"javascript\s*:", html, re.IGNORECASE):
        return False

    return True


@app.route("/action-firewall", methods=["POST"])
def action_firewall():
    data = request.get_json(silent=True)

    # --------------------------------------------------
    # 1. TOP-LEVEL SCHEMA
    # --------------------------------------------------
    if not isinstance(data, dict):
        return jsonify({
            "decision": "block",
            "reason": "INVALID_SCHEMA"
        })

    allowed_top_keys = {
        "provenance",
        "humanApproved",
        "untrustedContent",
        "action"
    }

    required_top_keys = {
        "provenance",
        "humanApproved",
        "action"
    }

    if not required_top_keys.issubset(data.keys()):
        return jsonify({
            "decision": "block",
            "reason": "INVALID_SCHEMA"
        })

    if not set(data.keys()).issubset(allowed_top_keys):
        return jsonify({
            "decision": "block",
            "reason": "INVALID_SCHEMA"
        })

    if data.get("provenance") not in ("trusted", "untrusted"):
        return jsonify({
            "decision": "block",
            "reason": "INVALID_SCHEMA"
        })

    if not isinstance(data.get("humanApproved"), bool):
        return jsonify({
            "decision": "block",
            "reason": "INVALID_SCHEMA"
        })

    if "untrustedContent" in data and not isinstance(
        data["untrustedContent"], str
    ):
        return jsonify({
            "decision": "block",
            "reason": "INVALID_SCHEMA"
        })

    action = data.get("action")

    if not isinstance(action, dict):
        return jsonify({
            "decision": "block",
            "reason": "INVALID_SCHEMA"
        })

    if not exact_keys(action, ["tool", "args"]):
        return jsonify({
            "decision": "block",
            "reason": "INVALID_SCHEMA"
        })

    if not isinstance(action["tool"], str):
        return jsonify({
            "decision": "block",
            "reason": "INVALID_SCHEMA"
        })

    args = action["args"]

    if not isinstance(args, dict):
        return jsonify({
            "decision": "block",
            "reason": "INVALID_SCHEMA"
        })

    tool = action["tool"]

    # --------------------------------------------------
    # 2. TOOL ALLOWLIST
    # --------------------------------------------------
    allowed_tools = {
        "search",
        "lookup_record",
        "send_email",
        "render_html"
    }

    if tool not in allowed_tools:
        return jsonify({
            "decision": "block",
            "reason": "TOOL_NOT_ALLOWED"
        })

    # --------------------------------------------------
    # 3. TOOL ARGUMENT SCHEMA
    # --------------------------------------------------

    # SEARCH
    if tool == "search":
        if not exact_keys(args, ["query"]):
            return jsonify({
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            })

        query = args["query"]

        if not isinstance(query, str):
            return jsonify({
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            })

        if not (1 <= len(query) <= 200):
            return jsonify({
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            })

        return jsonify({
            "decision": "allow",
            "reason": "ALLOW"
        })

    # LOOKUP_RECORD
    if tool == "lookup_record":
        if not exact_keys(args, ["tenantId", "recordId"]):
            return jsonify({
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            })

        if not isinstance(args["tenantId"], str):
            return jsonify({
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            })

        if not isinstance(args["recordId"], str) or not args["recordId"]:
            return jsonify({
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            })

        if args["tenantId"] != ASSIGNED_TENANT:
            return jsonify({
                "decision": "block",
                "reason": "TENANT_SCOPE"
            })

        return jsonify({
            "decision": "allow",
            "reason": "ALLOW"
        })

    # SEND_EMAIL
    if tool == "send_email":
        if not exact_keys(args, ["to", "subject", "body"]):
            return jsonify({
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            })

        if (
            not isinstance(args["to"], str)
            or not isinstance(args["subject"], str)
            or not isinstance(args["body"], str)
        ):
            return jsonify({
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            })

        # Exact recipient domain check
        recipient = args["to"]

        if "@" not in recipient:
            return jsonify({
                "decision": "block",
                "reason": "EGRESS_DENIED"
            })

        local_part, domain = recipient.rsplit("@", 1)

        if not local_part or domain != ALLOWED_EMAIL_DOMAIN:
            return jsonify({
                "decision": "block",
                "reason": "EGRESS_DENIED"
            })

        if data["humanApproved"] is not True:
            return jsonify({
                "decision": "block",
                "reason": "APPROVAL_REQUIRED"
            })

        return jsonify({
            "decision": "allow",
            "reason": "ALLOW"
        })

    # RENDER_HTML
    if tool == "render_html":
        if not exact_keys(args, ["html"]):
            return jsonify({
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            })

        if not isinstance(args["html"], str):
            return jsonify({
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            })

        if not valid_html(args["html"]):
            return jsonify({
                "decision": "block",
                "reason": "UNSAFE_OUTPUT"
            })

        return jsonify({
            "decision": "allow",
            "reason": "ALLOW"
        })



# ============================================================
# Q3 - Terraform Plan Policy Gate
# ============================================================

PROD_WORKSPACE = "prod-4qr8sw"

REQUIRED_LABELS = {
    "owner": "student-gy85i",
    "environment": "production",
    "cost_center": "cc-t9vg"
}

ALLOWED_BACKENDS = {
    "gcs",
    "s3",
    "azurerm",
    "remote"
}

STATEFUL_DELETE_TYPES = {
    "storage_bucket",
    "sql_database",
    "persistent_disk"
}


@app.route("/terraform/plan", methods=["POST"])
def terraform_plan():
    data = request.get_json(silent=True)

    # --------------------------------------------------------
    # 1. REQUEST / NESTED OBJECT TYPES
    # --------------------------------------------------------
    if not isinstance(data, dict):
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    required_top = {
        "environment",
        "state",
        "providerVersion",
        "destroyApproved",
        "resource"
    }

    if not required_top.issubset(data.keys()):
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    if not isinstance(data["environment"], str):
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    if not isinstance(data["providerVersion"], str):
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    if not isinstance(data["destroyApproved"], bool):
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    # State must be an object
    state = data["state"]

    if not isinstance(state, dict):
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    if "backend" not in state or "locked" not in state:
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    if not isinstance(state["backend"], str):
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    if not isinstance(state["locked"], bool):
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    # Resource must be an object
    resource = data["resource"]

    if not isinstance(resource, dict):
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    required_resource = {
        "address",
        "type",
        "action",
        "labels",
        "secret",
        "forceDestroy"
    }

    if not required_resource.issubset(resource.keys()):
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    if not isinstance(resource["address"], str):
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    if not isinstance(resource["type"], str):
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    if resource["action"] not in {"create", "update", "delete"}:
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    if not isinstance(resource["labels"], dict):
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    # Every label value should be a string
    for key, value in resource["labels"].items():
        if not isinstance(key, str) or not isinstance(value, str):
            return jsonify({
                "decision": "reject",
                "reason": "INVALID_PLAN"
            })

    # secret may be null or string
    if resource["secret"] is not None and not isinstance(
        resource["secret"], str
    ):
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    if not isinstance(resource["forceDestroy"], bool):
        return jsonify({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })

    # --------------------------------------------------------
    # 2. ENVIRONMENT
    # --------------------------------------------------------
    if data["environment"] != PROD_WORKSPACE:
        return jsonify({
            "decision": "reject",
            "reason": "ENVIRONMENT_MISMATCH"
        })

    # --------------------------------------------------------
    # 3. REMOTE STATE
    # --------------------------------------------------------
    if state["backend"] not in ALLOWED_BACKENDS:
        return jsonify({
            "decision": "reject",
            "reason": "STATE_UNSAFE"
        })

    if state["locked"] is not True:
        return jsonify({
            "decision": "reject",
            "reason": "STATE_UNSAFE"
        })

    # --------------------------------------------------------
    # 4. PROVIDER VERSION
    # --------------------------------------------------------
    provider = data["providerVersion"]

    if provider not in {
        "6.2.1",
        "= 6.2.1",
        "~> 6.0"
    }:
        return jsonify({
            "decision": "reject",
            "reason": "UNPINNED_PROVIDER"
        })

    # --------------------------------------------------------
    # 5. REQUIRED LABELS
    # --------------------------------------------------------
    labels = resource["labels"]

    for key, expected_value in REQUIRED_LABELS.items():
        if labels.get(key) != expected_value:
            return jsonify({
                "decision": "reject",
                "reason": "MISSING_LABELS"
            })

    # --------------------------------------------------------
    # 6. SECRET
    # --------------------------------------------------------
    secret = resource["secret"]

    if secret is not None:
        if not isinstance(secret, str):
            return jsonify({
                "decision": "reject",
                "reason": "PLAINTEXT_SECRET"
            })

        if not secret.startswith("secret://"):
            return jsonify({
                "decision": "reject",
                "reason": "PLAINTEXT_SECRET"
            })

        # Must have something after secret://
        if len(secret) <= len("secret://"):
            return jsonify({
                "decision": "reject",
                "reason": "PLAINTEXT_SECRET"
            })

    # --------------------------------------------------------
    # 7. STATEFUL DELETE APPROVAL
    # --------------------------------------------------------
    if (
        resource["action"] == "delete"
        and resource["type"] in STATEFUL_DELETE_TYPES
    ):
        if data["destroyApproved"] is not True:
            return jsonify({
                "decision": "reject",
                "reason": "DELETE_NOT_APPROVED"
            })

    # --------------------------------------------------------
    # 8. FORCE DESTROY
    # --------------------------------------------------------
    if (
        resource["type"] == "storage_bucket"
        and resource["forceDestroy"] is True
    ):
        return jsonify({
            "decision": "reject",
            "reason": "FORCE_DESTROY"
        })

    # --------------------------------------------------------
    # EVERYTHING PASSED
    # --------------------------------------------------------
    return jsonify({
        "decision": "approve",
        "reason": "APPROVE"
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)