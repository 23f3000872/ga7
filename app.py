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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)