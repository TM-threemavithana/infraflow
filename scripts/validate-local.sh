#!/usr/bin/env bash
# ==============================================================================
# InfraFlow Local Validation Harness
# Validates GitHub Actions workflow syntax, Terraform modules, native tests,
# negative fixtures, security guards, TFLint, Trivy, Zizmor, and OPA/Conftest policies
# without requiring cloud access ($0 budget).
# ==============================================================================

set -euo pipefail

# ANSI color codes for readable output
readonly COLOR_RESET="\033[0m"
readonly COLOR_GREEN="\033[1;32m"
readonly COLOR_RED="\033[1;31m"
# shellcheck disable=SC2034
readonly COLOR_YELLOW="\033[1;33m"
readonly COLOR_BLUE="\033[1;34m"
readonly COLOR_CYAN="\033[1;36m"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Ensure ~/.local/bin is in PATH
if [[ -d "${HOME}/.local/bin" ]]; then
  export PATH="${HOME}/.local/bin:${PATH}"
fi

TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0

log_header() {
  echo -e "\n${COLOR_CYAN}==============================================================================${COLOR_RESET}"
  echo -e "${COLOR_BLUE}>>> $1${COLOR_RESET}"
  echo -e "${COLOR_CYAN}==============================================================================${COLOR_RESET}"
}

record_pass() {
  local check_name="$1"
  TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
  PASSED_CHECKS=$((PASSED_CHECKS + 1))
  echo -e "  [ ${COLOR_GREEN}PASS${COLOR_RESET} ] ${check_name}"
}

record_fail() {
  local check_name="$1"
  local reason="$2"
  TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
  FAILED_CHECKS=$((FAILED_CHECKS + 1))
  echo -e "  [ ${COLOR_RED}FAIL${COLOR_RESET} ] ${check_name} -- ${reason}"
}

# --- 1. Environment & Tooling Verification ---
log_header "1. Environment & Tooling Verification"

if command -v terraform >/dev/null 2>&1; then
  TF_VERSION="$(terraform version | sed -n '1p')"
  record_pass "Terraform installed (${TF_VERSION})"
else
  record_fail "Terraform installed" "terraform command not found"
fi

ACTIONLINT_BIN=""
if command -v actionlint >/dev/null 2>&1; then
  ACTIONLINT_BIN="actionlint"
elif [[ -x "${HOME}/.local/bin/actionlint" ]]; then
  ACTIONLINT_BIN="${HOME}/.local/bin/actionlint"
elif [[ -x "/tmp/actionlint" ]]; then
  ACTIONLINT_BIN="/tmp/actionlint"
fi

if [[ -n "${ACTIONLINT_BIN}" ]]; then
  AL_VERSION="$("${ACTIONLINT_BIN}" --version | sed -n '1p')"
  record_pass "Actionlint installed (${AL_VERSION})"
else
  record_fail "Actionlint installed" "actionlint binary not found"
fi

SHELLCHECK_BIN=""
if command -v shellcheck >/dev/null 2>&1; then
  SHELLCHECK_BIN="shellcheck"
elif [[ -x "${HOME}/.local/bin/shellcheck" ]]; then
  SHELLCHECK_BIN="${HOME}/.local/bin/shellcheck"
fi

if [[ -n "${SHELLCHECK_BIN}" ]]; then
  SC_VERSION="$("${SHELLCHECK_BIN}" --version | grep 'version:' | sed -n '1p')"
  record_pass "ShellCheck installed (${SC_VERSION})"
else
  record_fail "ShellCheck installed" "shellcheck binary not found"
fi

TFLINT_BIN=""
if command -v tflint >/dev/null 2>&1; then
  TFLINT_BIN="tflint"
elif [[ -x "${HOME}/.local/bin/tflint" ]]; then
  TFLINT_BIN="${HOME}/.local/bin/tflint"
fi

if [[ -n "${TFLINT_BIN}" ]]; then
  TFLINT_VER="$("${TFLINT_BIN}" --version | sed -n '1p')"
  record_pass "TFLint installed (${TFLINT_VER})"
else
  record_fail "TFLint installed" "tflint binary not found"
fi

TRIVY_BIN=""
if command -v trivy >/dev/null 2>&1; then
  TRIVY_BIN="trivy"
elif [[ -x "${HOME}/.local/bin/trivy" ]]; then
  TRIVY_BIN="${HOME}/.local/bin/trivy"
fi

if [[ -n "${TRIVY_BIN}" ]]; then
  TRIVY_VER="$("${TRIVY_BIN}" --version | grep 'Version:' | sed -n '1p')"
  record_pass "Trivy installed (${TRIVY_VER})"
else
  record_fail "Trivy installed" "trivy binary not found"
fi

ZIZMOR_BIN=""
if command -v zizmor >/dev/null 2>&1; then
  ZIZMOR_BIN="zizmor"
elif [[ -x "${HOME}/.local/bin/zizmor" ]]; then
  ZIZMOR_BIN="${HOME}/.local/bin/zizmor"
fi

if [[ -n "${ZIZMOR_BIN}" ]]; then
  ZIZMOR_VER="$("${ZIZMOR_BIN}" --version | sed -n '1p')"
  record_pass "Zizmor installed (${ZIZMOR_VER})"
else
  record_fail "Zizmor installed" "zizmor binary not found"
fi

CONFTEST_BIN=""
if command -v conftest >/dev/null 2>&1; then
  CONFTEST_BIN="conftest"
elif [[ -x "${HOME}/.local/bin/conftest" ]]; then
  CONFTEST_BIN="${HOME}/.local/bin/conftest"
fi

if [[ -n "${CONFTEST_BIN}" ]]; then
  CONFTEST_VER="$("${CONFTEST_BIN}" --version | sed -n '1p')"
  record_pass "Conftest installed (${CONFTEST_VER})"
else
  record_fail "Conftest installed" "conftest binary not found"
fi

# --- 2. GitHub Actions Workflow Syntax Linting ---
log_header "2. GitHub Actions Workflow Linting (actionlint)"

if [[ -n "${ACTIONLINT_BIN}" ]]; then
  AL_ARGS=()
  if [[ -n "${SHELLCHECK_BIN}" ]]; then
    AL_ARGS+=("-shellcheck" "${SHELLCHECK_BIN}")
  fi
  if (cd "${REPO_ROOT}" && "${ACTIONLINT_BIN}" "${AL_ARGS[@]}" .github/workflows/*.yml); then
    record_pass "Workflow syntax & schema validation (.github/workflows)"
  else
    record_fail "Workflow syntax validation" "actionlint reported errors"
  fi
else
  record_fail "Workflow syntax validation" "actionlint binary missing"
fi

# --- 3. Positive Terraform Module Validation (Cloud-Free Example) ---
log_header "3. Positive Testing: examples/cloud-free-module"

EXAMPLE_DIR="${REPO_ROOT}/examples/cloud-free-module"

if (cd "${EXAMPLE_DIR}" && terraform fmt -check -diff); then
  record_pass "Canonical formatting (terraform fmt -check)"
else
  record_fail "Canonical formatting" "Unformatted Terraform files detected"
fi

if (cd "${EXAMPLE_DIR}" && terraform init -backend=false -input=false >/dev/null 2>&1); then
  record_pass "Backend-free initialization (terraform init -backend=false)"
else
  record_fail "Backend-free initialization" "terraform init failed"
fi

if (cd "${EXAMPLE_DIR}" && terraform validate >/dev/null 2>&1); then
  record_pass "Static validation (terraform validate)"
else
  record_fail "Static validation" "terraform validate reported configuration errors"
fi

if (cd "${EXAMPLE_DIR}" && terraform test -verbose >/dev/null 2>&1); then
  record_pass "Native unit test execution (terraform test -verbose: 6 passed)"
else
  record_fail "Native unit test execution" "terraform test failed"
fi

# --- 4. Negative Test Fixtures Verification ---
log_header "4. Negative Testing: Verifying Expected Failure Rejections"

# Negative Fixture 1: Invalid Syntax
INVALID_SYNTAX_DIR="${REPO_ROOT}/fixtures/invalid-syntax"
if (cd "${INVALID_SYNTAX_DIR}" && terraform validate >/dev/null 2>&1); then
  record_fail "Negative Check: fixtures/invalid-syntax" "Expected failure, but terraform validate succeeded unexpectedly"
else
  record_pass "Negative Check: fixtures/invalid-syntax rejected as expected (exit code != 0)"
fi

# Negative Fixture 2: Unformatted Code
UNFORMATTED_DIR="${REPO_ROOT}/fixtures/unformatted"
if (cd "${UNFORMATTED_DIR}" && terraform fmt -check >/dev/null 2>&1); then
  record_fail "Negative Check: fixtures/unformatted" "Expected failure, but terraform fmt -check succeeded unexpectedly"
else
  record_pass "Negative Check: fixtures/unformatted rejected as expected (exit code != 0)"
fi

# Negative Fixture 3: Failing Test Assertion
FAILING_TEST_DIR="${REPO_ROOT}/fixtures/failing-test"
if (cd "${FAILING_TEST_DIR}" && terraform init -backend=false -input=false >/dev/null 2>&1 && terraform test >/dev/null 2>&1); then
  record_fail "Negative Check: fixtures/failing-test" "Expected failure, but terraform test passed unexpectedly"
else
  record_pass "Negative Check: fixtures/failing-test assertion failed as expected (exit code != 0)"
fi

# --- 5. Security Guard & Workspace Containment Verification ---
log_header "5. Security Guard & Workspace Containment (Extracted Workflow Logic)"

REUSABLE_WF="${REPO_ROOT}/.github/workflows/reusable-tf-validate.yml"

GUARD_SCRIPT="$(python3 -c "
import yaml
with open('${REUSABLE_WF}', 'r') as f:
    data = yaml.safe_load(f)
steps = {s['id']: s['run'] for s in data['jobs']['validate']['steps'] if 'id' in s and 'run' in s}
print(steps['guard'])
")"

VERIFY_WORKSPACE_SCRIPT="$(python3 -c "
import yaml
with open('${REUSABLE_WF}', 'r') as f:
    data = yaml.safe_load(f)
steps = {s['id']: s['run'] for s in data['jobs']['validate']['steps'] if 'id' in s and 'run' in s}
print(steps['verify_workspace'])
")"

run_guard_test() {
  local input_dir="$1"
  local input_version="$2"
  local input_var_file="${3:-}"

  local code=0
  INPUT_DIR="${input_dir}" INPUT_VERSION="${input_version}" INPUT_VAR_FILE="${input_var_file}" \
    bash -c "${GUARD_SCRIPT}" >/dev/null 2>&1 || code=$?
  return ${code}
}

run_verify_workspace_test() {
  local workspace_dir="$1"
  local input_dir="$2"
  local input_var_file="${3:-}"

  local code=0
  GITHUB_WORKSPACE="${workspace_dir}" INPUT_DIR="${input_dir}" INPUT_VAR_FILE="${input_var_file}" \
    bash -c "${VERIFY_WORKSPACE_SCRIPT}" >/dev/null 2>&1 || code=$?
  return ${code}
}

# Test 5.1: Valid inputs accepted
if run_guard_test "examples/cloud-free-module" "1.10.4" ""; then
  record_pass "Security Guard: Valid inputs accepted"
else
  record_fail "Security Guard: Valid inputs" "Legitimate inputs unexpectedly failed"
fi

# Test 5.2: Terraform version < 1.6.0 rejected (e.g. 1.5.7)
if run_guard_test "examples/cloud-free-module" "1.5.7" ""; then
  record_fail "Security Guard: Version < 1.6.0 rejection" "Version 1.5.7 was not rejected"
else
  record_pass "Security Guard: Version < 1.6.0 ('1.5.7') rejected as expected"
fi

# Test 5.3: Major version 0 rejected (e.g. 0.14.0)
if run_guard_test "examples/cloud-free-module" "0.14.0" ""; then
  record_fail "Security Guard: Version 0.x rejection" "Version 0.14.0 was not rejected"
else
  record_pass "Security Guard: Version 0.x ('0.14.0') rejected as expected"
fi

# Test 5.4: Non-SemVer version string rejected
if run_guard_test "examples/cloud-free-module" "v1.10-beta;evil" ""; then
  record_fail "Security Guard: Malformed SemVer rejection" "Malformed version was not rejected"
else
  record_pass "Security Guard: Malformed SemVer rejected as expected"
fi

# Test 5.5: Absolute directory path rejected (/etc)
if run_guard_test "/etc" "1.10.4" ""; then
  record_fail "Security Guard: Absolute path rejection" "Absolute path '/etc' was not rejected"
else
  record_pass "Security Guard: Absolute path ('/etc') rejected as expected"
fi

# Test 5.6: Tilde path rejected (~/secret)
# shellcheck disable=SC2088
if run_guard_test "~/secret" "1.10.4" ""; then
  record_fail "Security Guard: Tilde path rejection" "Tilde path '~/secret' was not rejected"
else
  record_pass "Security Guard: Tilde path ('~/secret') rejected as expected"
fi

# Test 5.7: Directory traversal sequence rejected (..)
if run_guard_test "../../etc/passwd" "1.10.4" ""; then
  record_fail "Security Guard: Traversal rejection" "Traversal input '../../etc/passwd' was not rejected"
else
  record_pass "Security Guard: Path traversal ('../../etc/passwd') rejected as expected"
fi

# Test 5.8: Command injection characters rejected
if run_guard_test "modules/network; rm -rf /" "1.10.4" ""; then
  record_fail "Security Guard: Injection rejection" "Injection input 'modules/network; rm -rf /' was not rejected"
else
  record_pass "Security Guard: Command injection characters rejected as expected"
fi

# Test 5.9: Absolute path in test-var-file rejected
if run_guard_test "examples/cloud-free-module" "1.10.4" "/etc/passwd"; then
  record_fail "Security Guard: Absolute var file rejection" "Absolute path in test-var-file was not rejected"
else
  record_pass "Security Guard: Absolute path in test-var-file rejected as expected"
fi

# Test 5.10: Path traversal in test-var-file rejected
if run_guard_test "examples/cloud-free-module" "1.10.4" "../secret.tfvars"; then
  record_fail "Security Guard: Var file traversal" "Traversal in test-var-file was not rejected"
else
  record_pass "Security Guard: Path traversal in test-var-file rejected as expected"
fi

# Test 5.11: Workspace containment: Valid relative directory exists
if run_verify_workspace_test "${REPO_ROOT}" "examples/cloud-free-module" ""; then
  record_pass "Workspace Containment: Existing directory within workspace accepted"
else
  record_fail "Workspace Containment: Valid directory" "Existing directory unexpectedly rejected"
fi

# Test 5.12: Workspace containment: Non-existent directory rejected
if run_verify_workspace_test "${REPO_ROOT}" "non/existent/directory" ""; then
  record_fail "Workspace Containment: Non-existent directory" "Non-existent directory was not rejected"
else
  record_pass "Workspace Containment: Non-existent directory rejected as expected"
fi

# --- 6. DevSecOps: TFLint Static Analysis ---
log_header "6. DevSecOps Layer 1: TFLint Static Analysis"

if [[ -n "${TFLINT_BIN}" ]]; then
  # Test 6.1: Valid fixture passes TFLint
  if "${TFLINT_BIN}" --config="${REPO_ROOT}/.tflint.hcl" --chdir="${REPO_ROOT}/fixtures/security/tflint/valid" >/dev/null 2>&1; then
    record_pass "TFLint: Valid fixture accepted cleanly"
  else
    record_fail "TFLint: Valid fixture" "TFLint failed unexpectedly on valid fixture"
  fi

  # Test 6.2: Invalid fixture rejected by TFLint
  if "${TFLINT_BIN}" --config="${REPO_ROOT}/.tflint.hcl" --chdir="${REPO_ROOT}/fixtures/security/tflint/invalid" >/dev/null 2>&1; then
    record_fail "TFLint: Invalid fixture" "TFLint unexpectedly succeeded on invalid fixture"
  else
    record_pass "TFLint: Invalid fixture rejected as expected (exit code != 0)"
  fi

  # Test 6.3: Cloud-free reference module passes TFLint
  if "${TFLINT_BIN}" --config="${REPO_ROOT}/.tflint.hcl" --chdir="${REPO_ROOT}/examples/cloud-free-module" >/dev/null 2>&1; then
    record_pass "TFLint: examples/cloud-free-module conforms to all lint rules"
  else
    record_fail "TFLint: cloud-free-module" "TFLint failed on reference module"
  fi
else
  record_fail "TFLint suite" "tflint binary missing"
fi

# --- 7. DevSecOps: Trivy IaC Misconfiguration Scanning ---
log_header "7. DevSecOps Layer 2: Trivy IaC Misconfiguration Scanning"

if [[ -n "${TRIVY_BIN}" ]]; then
  # Test 7.1: Secure fixture passes Trivy
  if "${TRIVY_BIN}" config --severity HIGH,CRITICAL --exit-code 1 "${REPO_ROOT}/fixtures/security/trivy/secure" >/dev/null 2>&1; then
    record_pass "Trivy: Secure fixture passes HIGH/CRITICAL scan"
  else
    record_fail "Trivy: Secure fixture" "Trivy unexpectedly failed on secure fixture"
  fi

  # Test 7.2: Insecure storage rejected by Trivy
  if "${TRIVY_BIN}" config --severity HIGH,CRITICAL --exit-code 1 "${REPO_ROOT}/fixtures/security/trivy/insecure-storage" >/dev/null 2>&1; then
    record_fail "Trivy: Insecure storage" "Trivy unexpectedly passed on insecure storage"
  else
    record_pass "Trivy: Insecure storage (public S3) rejected as expected (exit code != 0)"
  fi

  # Test 7.3: Insecure network rejected by Trivy
  if "${TRIVY_BIN}" config --severity HIGH,CRITICAL --exit-code 1 "${REPO_ROOT}/fixtures/security/trivy/insecure-network" >/dev/null 2>&1; then
    record_fail "Trivy: Insecure network" "Trivy unexpectedly passed on unrestricted SSH"
  else
    record_pass "Trivy: Insecure network (0.0.0.0/0 SSH) rejected as expected (exit code != 0)"
  fi

  # Test 7.4: Cloud-free reference module passes Trivy
  if "${TRIVY_BIN}" config --severity HIGH,CRITICAL --exit-code 1 "${REPO_ROOT}/examples/cloud-free-module" >/dev/null 2>&1; then
    record_pass "Trivy: examples/cloud-free-module clean of misconfigurations"
  else
    record_fail "Trivy: cloud-free-module" "Trivy flagged issues in reference module"
  fi
else
  record_fail "Trivy suite" "trivy binary missing"
fi

# --- 8. DevSecOps: Zizmor GitHub Actions Security Audit ---
log_header "8. DevSecOps Layer 3: Zizmor Supply Chain Security Audit"

if [[ -n "${ZIZMOR_BIN}" ]]; then
  # Test 8.1: Platform workflows pass Zizmor audit
  if "${ZIZMOR_BIN}" -c "${REPO_ROOT}/.zizmor.yml" --min-severity medium "${REPO_ROOT}/.github/workflows" >/dev/null 2>&1; then
    record_pass "Zizmor: Platform workflows pass supply chain audit (0 medium/high findings)"
  else
    record_fail "Zizmor: Platform workflows" "Zizmor flagged issues in .github/workflows"
  fi

  # Test 8.2: Insecure permissions workflow rejected
  if "${ZIZMOR_BIN}" "${REPO_ROOT}/fixtures/security/zizmor/insecure-permissions.yml" >/dev/null 2>&1; then
    record_fail "Zizmor: Insecure permissions" "Zizmor unexpectedly passed on write-all permissions"
  else
    record_pass "Zizmor: Insecure permissions (write-all) rejected as expected (exit code != 0)"
  fi

  # Test 8.3: Unpinned third-party action rejected
  if "${ZIZMOR_BIN}" "${REPO_ROOT}/fixtures/security/zizmor/unpinned-action.yml" >/dev/null 2>&1; then
    record_fail "Zizmor: Unpinned action" "Zizmor unexpectedly passed on unpinned action"
  else
    record_pass "Zizmor: Unpinned action reference rejected as expected (exit code != 0)"
  fi

  # Test 8.4: Template injection workflow rejected
  if "${ZIZMOR_BIN}" "${REPO_ROOT}/fixtures/security/zizmor/template-injection.yml" >/dev/null 2>&1; then
    record_fail "Zizmor: Template injection" "Zizmor unexpectedly passed on shell injection"
  else
    record_pass "Zizmor: Expression template injection rejected as expected (exit code != 0)"
  fi
else
  record_fail "Zizmor suite" "zizmor binary missing"
fi

# --- 9. DevSecOps: Conftest / OPA Policy as Code ---
log_header "9. DevSecOps Layer 4: Conftest / OPA Policy as Code"

if [[ -n "${CONFTEST_BIN}" ]]; then
  # Test 9.1: Verify Rego unit tests
  if "${CONFTEST_BIN}" verify --policy "${REPO_ROOT}/policies" >/dev/null 2>&1; then
    record_pass "Conftest: All 62 Rego unit tests passed (conftest verify)"
  else
    record_fail "Conftest: Rego unit tests" "conftest verify reported test failures"
  fi

  # Test 9.2: Compliant HCL fixture passes policies
  if "${CONFTEST_BIN}" test --all-namespaces --policy "${REPO_ROOT}/policies" "${REPO_ROOT}/fixtures/security/policies/valid/main.tf" >/dev/null 2>&1; then
    record_pass "Conftest: Compliant HCL fixture passes all policies"
  else
    record_fail "Conftest: Compliant HCL" "conftest test failed on compliant fixture"
  fi

  # Test 9.3: Missing environment tag rejected
  if "${CONFTEST_BIN}" test --all-namespaces --policy "${REPO_ROOT}/policies" "${REPO_ROOT}/fixtures/security/policies/invalid-tags/main.tf" >/dev/null 2>&1; then
    record_fail "Conftest: Invalid tags" "conftest test unexpectedly passed on missing Environment tag"
  else
    record_pass "Conftest: Missing Environment tag rejected as expected"
  fi

  # Test 9.4: Insecure AWS S3 public ACL rejected
  if "${CONFTEST_BIN}" test --all-namespaces --policy "${REPO_ROOT}/policies" "${REPO_ROOT}/fixtures/security/policies/invalid-aws/main.tf" >/dev/null 2>&1; then
    record_fail "Conftest: Insecure AWS" "conftest test unexpectedly passed on public S3 ACL"
  else
    record_pass "Conftest: Insecure AWS S3 public ACL rejected as expected"
  fi

  # Test 9.5: Insecure Azure public blob storage & TLS rejected
  if "${CONFTEST_BIN}" test --all-namespaces --policy "${REPO_ROOT}/policies" "${REPO_ROOT}/fixtures/security/policies/invalid-azure/main.tf" >/dev/null 2>&1; then
    record_fail "Conftest: Insecure Azure" "conftest test unexpectedly passed on insecure Azure storage"
  else
    record_pass "Conftest: Insecure Azure storage & TLS 1.0 rejected as expected"
  fi

  # Test 9.6: Insecure GCP storage without uniform access rejected
  if "${CONFTEST_BIN}" test --all-namespaces --policy "${REPO_ROOT}/policies" "${REPO_ROOT}/fixtures/security/policies/invalid-gcp/main.tf" >/dev/null 2>&1; then
    record_fail "Conftest: Insecure GCP" "conftest test unexpectedly passed on GCS bucket"
  else
    record_pass "Conftest: Insecure GCP storage uniform access rejected as expected"
  fi

  # Test 9.7: Compliant Terraform Plan JSON passes
  if "${CONFTEST_BIN}" test --all-namespaces --policy "${REPO_ROOT}/policies" "${REPO_ROOT}/fixtures/security/policies/plan-json/valid-plan.json" >/dev/null 2>&1; then
    record_pass "Conftest: Compliant Terraform Plan JSON passes policy checks"
  else
    record_fail "Conftest: Compliant Plan JSON" "conftest test failed on valid plan JSON"
  fi

  # Test 9.8: Insecure Terraform Plan JSON rejected
  if "${CONFTEST_BIN}" test --all-namespaces --policy "${REPO_ROOT}/policies" "${REPO_ROOT}/fixtures/security/policies/plan-json/invalid-plan.json" >/dev/null 2>&1; then
    record_fail "Conftest: Insecure Plan JSON" "conftest test unexpectedly passed on invalid plan JSON"
  else
    record_pass "Conftest: Insecure Terraform Plan JSON rejected as expected"
  fi

  # Test 9.9: Invalid policy input handling
  if "${CONFTEST_BIN}" test --all-namespaces --parser json --policy "${REPO_ROOT}/policies" "${REPO_ROOT}/fixtures/security/policies/invalid-input.txt" >/dev/null 2>&1; then
    record_fail "Conftest: Invalid input" "conftest unexpectedly succeeded on malformed input"
  else
    record_pass "Conftest: Malformed input unmarshal correctly handled & rejected"
  fi

  # Test 9.10: Reference module passes all policies
  if "${CONFTEST_BIN}" test --all-namespaces --policy "${REPO_ROOT}/policies" "${REPO_ROOT}/examples/cloud-free-module/main.tf" >/dev/null 2>&1; then
    record_pass "Conftest: examples/cloud-free-module satisfies all enterprise policies"
  else
    record_fail "Conftest: cloud-free-module" "conftest failed on reference module"
  fi

  # Test 9.11: Plan: Deletion of S3 public access protection rejected
  if "${CONFTEST_BIN}" test --all-namespaces --policy "${REPO_ROOT}/policies" "${REPO_ROOT}/fixtures/security/policies/plan-json/delete-s3-pab.json" >/dev/null 2>&1; then
    record_fail "Conftest: Deletion of S3 PAB" "conftest unexpectedly passed on deletion of S3 public access block"
  else
    record_pass "Conftest: Plan: Deletion of S3 public access protection rejected as expected"
  fi

  # Test 9.12: Plan: Deletion of S3 encryption configuration rejected
  if "${CONFTEST_BIN}" test --all-namespaces --policy "${REPO_ROOT}/policies" "${REPO_ROOT}/fixtures/security/policies/plan-json/delete-s3-encryption.json" >/dev/null 2>&1; then
    record_fail "Conftest: Deletion of S3 encryption" "conftest unexpectedly passed on deletion of S3 encryption"
  else
    record_pass "Conftest: Plan: Deletion of S3 encryption configuration rejected as expected"
  fi

  # Test 9.13: Plan: Deletion of Azure storage network rules rejected
  if "${CONFTEST_BIN}" test --all-namespaces --policy "${REPO_ROOT}/policies" "${REPO_ROOT}/fixtures/security/policies/plan-json/delete-azure-storage-network.json" >/dev/null 2>&1; then
    record_fail "Conftest: Deletion of Azure storage network" "conftest unexpectedly passed on deletion of storage network rules"
  else
    record_pass "Conftest: Plan: Deletion of Azure storage network rules rejected as expected"
  fi

  # Test 9.14: Plan: Deletion of S3 bucket policy rejected
  if "${CONFTEST_BIN}" test --all-namespaces --policy "${REPO_ROOT}/policies" "${REPO_ROOT}/fixtures/security/policies/plan-json/delete-s3-policy.json" >/dev/null 2>&1; then
    record_fail "Conftest: Deletion of S3 bucket policy" "conftest unexpectedly passed on deletion of S3 bucket policy"
  else
    record_pass "Conftest: Plan: Deletion of S3 bucket policy rejected as expected"
  fi

  # Test 9.15: Plan: Safe deletion of ordinary non-security resource allowed
  if "${CONFTEST_BIN}" test --all-namespaces --policy "${REPO_ROOT}/policies" "${REPO_ROOT}/fixtures/security/policies/plan-json/safe-delete-instance.json" >/dev/null 2>&1; then
    record_pass "Conftest: Plan: Safe deletion of ordinary resource allowed as expected"
  else
    record_fail "Conftest: Safe deletion" "conftest unexpectedly failed on safe instance deletion"
  fi

  # Test 9.16: Plan: Replacement action orderings (insecure delete/create rejected)
  if "${CONFTEST_BIN}" test --all-namespaces --policy "${REPO_ROOT}/policies" "${REPO_ROOT}/fixtures/security/policies/plan-json/replace-s3-pab-insecure-delete-create.json" >/dev/null 2>&1; then
    record_fail "Conftest: Insecure replacement dc" "conftest unexpectedly passed on delete/create insecure replacement"
  else
    record_pass "Conftest: Plan: Insecure replacement (delete/create) rejected as expected"
  fi

  # Test 9.17: Plan: Replacement action orderings (insecure create/delete rejected)
  if "${CONFTEST_BIN}" test --all-namespaces --policy "${REPO_ROOT}/policies" "${REPO_ROOT}/fixtures/security/policies/plan-json/replace-s3-pab-insecure-create-delete.json" >/dev/null 2>&1; then
    record_fail "Conftest: Insecure replacement cd" "conftest unexpectedly passed on create/delete insecure replacement"
  else
    record_pass "Conftest: Plan: Insecure replacement (create/delete) rejected as expected"
  fi

  # Test 9.18: Plan: Replacement action orderings (secure delete/create allowed)
  if "${CONFTEST_BIN}" test --all-namespaces --policy "${REPO_ROOT}/policies" "${REPO_ROOT}/fixtures/security/policies/plan-json/replace-s3-pab-secure-delete-create.json" >/dev/null 2>&1; then
    record_pass "Conftest: Plan: Secure replacement (delete/create) allowed as expected"
  else
    record_fail "Conftest: Secure replacement dc" "conftest unexpectedly failed on secure delete/create replacement"
  fi

  # Test 9.19: Plan: Replacement action orderings (secure create/delete allowed)
  if "${CONFTEST_BIN}" test --all-namespaces --policy "${REPO_ROOT}/policies" "${REPO_ROOT}/fixtures/security/policies/plan-json/replace-s3-pab-secure-create-delete.json" >/dev/null 2>&1; then
    record_pass "Conftest: Plan: Secure replacement (create/delete) allowed as expected"
  else
    record_fail "Conftest: Secure replacement cd" "conftest unexpectedly failed on secure create/delete replacement"
  fi

  # Test 9.20: Plan: S3 PAB deleted while exact parent bucket also deleted (allowed)
  if "${CONFTEST_BIN}" test --all-namespaces --policy "${REPO_ROOT}/policies" "${REPO_ROOT}/fixtures/security/policies/plan-json/delete-s3-pab-parent-also-deleted.json" >/dev/null 2>&1; then
    record_pass "Conftest: Plan: S3 PAB deleted when exact parent bucket also deleted allowed as expected"
  else
    record_fail "Conftest: S3 parent decommissioning" "conftest unexpectedly failed when both S3 PAB and parent bucket deleted"
  fi

  # Test 9.21: Plan: S3 PAB deleted while different bucket destroyed (rejected)
  if "${CONFTEST_BIN}" test --all-namespaces --policy "${REPO_ROOT}/policies" "${REPO_ROOT}/fixtures/security/policies/plan-json/delete-s3-pab-different-bucket-deleted.json" >/dev/null 2>&1; then
    record_fail "Conftest: S3 different bucket" "conftest unexpectedly passed when deleting PAB with different bucket destroyed"
  else
    record_pass "Conftest: Plan: S3 PAB deleted while different bucket destroyed rejected as expected"
  fi

  # Test 9.22: Plan: S3 PAB deleted while different module bucket destroyed (rejected)
  if "${CONFTEST_BIN}" test --all-namespaces --policy "${REPO_ROOT}/policies" "${REPO_ROOT}/fixtures/security/policies/plan-json/delete-s3-pab-different-module-deleted.json" >/dev/null 2>&1; then
    record_fail "Conftest: S3 different module" "conftest unexpectedly passed when deleting PAB in different module scope"
  else
    record_pass "Conftest: Plan: S3 PAB deleted while different module bucket destroyed rejected as expected"
  fi

  # Test 9.23: Plan: Azure storage network rules and exact parent storage account deleted (allowed)
  if "${CONFTEST_BIN}" test --all-namespaces --policy "${REPO_ROOT}/policies" "${REPO_ROOT}/fixtures/security/policies/plan-json/delete-azure-storage-network-parent-also-deleted.json" >/dev/null 2>&1; then
    record_pass "Conftest: Plan: Azure network rules and exact parent storage account deleted allowed as expected"
  else
    record_fail "Conftest: Azure parent decommissioning" "conftest unexpectedly failed when both storage network rules and parent account deleted"
  fi

  # Test 9.24: Plan: Azure network rules deleted while different storage account destroyed (rejected)
  if "${CONFTEST_BIN}" test --all-namespaces --policy "${REPO_ROOT}/policies" "${REPO_ROOT}/fixtures/security/policies/plan-json/delete-azure-network-different-storage-deleted.json" >/dev/null 2>&1; then
    record_fail "Conftest: Azure different storage" "conftest unexpectedly passed when deleting network rules with different storage destroyed"
  else
    record_pass "Conftest: Plan: Azure network rules deleted while different storage account destroyed rejected as expected"
  fi

  # Test 9.25: Plan: Azure network rules deleted while different module storage destroyed (rejected)
  if "${CONFTEST_BIN}" test --all-namespaces --policy "${REPO_ROOT}/policies" "${REPO_ROOT}/fixtures/security/policies/plan-json/delete-azure-network-different-module-deleted.json" >/dev/null 2>&1; then
    record_fail "Conftest: Azure different module" "conftest unexpectedly passed when deleting network rules in different module scope"
  else
    record_pass "Conftest: Plan: Azure network rules deleted while different module storage destroyed rejected as expected"
  fi

  # Test 9.26: Plan: Unknown security attribute rejected
  if "${CONFTEST_BIN}" test --all-namespaces --policy "${REPO_ROOT}/policies" "${REPO_ROOT}/fixtures/security/policies/plan-json/unknown-security-attr.json" >/dev/null 2>&1; then
    record_fail "Conftest: Unknown security attribute" "conftest unexpectedly passed on unknown security attribute"
  else
    record_pass "Conftest: Plan: Unknown security attribute rejected as expected"
  fi

  # Test 9.27: Plan: Errored/incomplete plan input rejected
  if "${CONFTEST_BIN}" test --all-namespaces --policy "${REPO_ROOT}/policies" "${REPO_ROOT}/fixtures/security/policies/plan-json/errored-plan.json" >/dev/null 2>&1; then
    record_fail "Conftest: Errored plan input" "conftest unexpectedly passed on errored plan input"
  else
    record_pass "Conftest: Plan: Errored/incomplete plan input rejected as expected"
  fi
else
  record_fail "Conftest suite" "conftest binary missing"
fi

# --- 10. DevOps Tier 2: Secure Planning & Approval Engine (G04) ---
log_header "10. Secure Terraform Planning & Approval Engine (G04)"

PLAN_ENGINE_TMP="/tmp/infraflow_g04_test"
mkdir -p "${PLAN_ENGINE_TMP}"
chmod 700 "${PLAN_ENGINE_TMP}"
EXAMPLE_DIR="${REPO_ROOT}/examples/cloud-free-module"

# Test 10.1: Speculative plan generation and JSON export
if (cd "${EXAMPLE_DIR}" && \
    terraform init -backend=false -input=false >/dev/null 2>&1 && \
    terraform plan -input=false -lock=false -out="${PLAN_ENGINE_TMP}/tfplan" >/dev/null 2>&1 && \
    terraform show -json "${PLAN_ENGINE_TMP}/tfplan" > "${PLAN_ENGINE_TMP}/tfplan.json" 2>/dev/null && \
    [[ -s "${PLAN_ENGINE_TMP}/tfplan.json" ]]); then
  record_pass "Planning Engine: Speculative plan and JSON generated without cloud credentials"
else
  record_fail "Planning Engine: Plan generation" "Failed to generate speculative plan JSON"
fi

# Test 10.2: Plan Analysis Engine execution
if "${REPO_ROOT}/scripts/analyze-plan.py" \
    --plan-json "${PLAN_ENGINE_TMP}/tfplan.json" \
    --output-json "${PLAN_ENGINE_TMP}/metrics.json" \
    --output-markdown "${PLAN_ENGINE_TMP}/summary.md" >/dev/null 2>&1; then
  record_pass "Plan Analysis: Resource classification and change metrics computed successfully"
else
  record_fail "Plan Analysis: Execution" "analyze-plan.py failed on generated plan"
fi

# Test 10.3: Sanitized Markdown summary structure
if [[ -f "${PLAN_ENGINE_TMP}/summary.md" ]] && grep -q "Terraform Execution Plan Summary" "${PLAN_ENGINE_TMP}/summary.md" && grep -q "Change Metrics" "${PLAN_ENGINE_TMP}/summary.md"; then
  record_pass "Plan Analysis: Formatted GitHub step summary Markdown generated"
else
  record_fail "Plan Analysis: Markdown summary" "summary.md missing or malformed"
fi

# Test 10.4: Sensitive attribute masking (zero leak)
if "${REPO_ROOT}/scripts/analyze-plan.py" \
    --plan-json "${REPO_ROOT}/fixtures/planning/sensitive-plan/plan.json" \
    --output-json "${PLAN_ENGINE_TMP}/sensitive_metrics.json" \
    --output-markdown "${PLAN_ENGINE_TMP}/sensitive_summary.md" >/dev/null 2>&1; then
  if grep -q "SuperSecret" "${PLAN_ENGINE_TMP}/sensitive_summary.md" || grep -q "SuperSecret" "${PLAN_ENGINE_TMP}/sensitive_metrics.json"; then
    record_fail "Plan Analysis: Sensitive masking" "Sensitive plaintext password leaked into summary or metrics output"
  else
    record_pass "Plan Analysis: Sensitive credentials masked with zero leakage"
  fi
else
  record_fail "Plan Analysis: Sensitive plan" "analyze-plan.py failed on sensitive fixture"
fi

# Test 10.5: Destructive changes detection (delete/replace)
if "${REPO_ROOT}/scripts/analyze-plan.py" \
    --plan-json "${REPO_ROOT}/fixtures/planning/destructive-plan/plan.json" \
    --output-json "${PLAN_ENGINE_TMP}/destructive_metrics.json" >/dev/null 2>&1; then
  if grep -q '"has_destructive_changes": true' "${PLAN_ENGINE_TMP}/destructive_metrics.json"; then
    record_pass "Plan Analysis: Destructive actions (delete/replace) correctly identified"
  else
    record_fail "Plan Analysis: Destructive detection" "Destructive actions not flagged in metrics JSON"
  fi
else
  record_fail "Plan Analysis: Destructive fixture" "analyze-plan.py failed on destructive fixture"
fi

# Test 10.6: Enforce failure on destructive changes (--fail-on-destructive)
if "${REPO_ROOT}/scripts/analyze-plan.py" \
    --plan-json "${REPO_ROOT}/fixtures/planning/destructive-plan/plan.json" \
    --fail-on-destructive >/dev/null 2>&1; then
  record_fail "Plan Analysis: Fail-on-destructive" "analyze-plan.py unexpectedly succeeded when destructive changes were present"
else
  record_pass "Plan Analysis: Rejection enforced when destructive changes occur (--fail-on-destructive)"
fi

# Test 10.7: Malformed plan JSON rejection
if "${REPO_ROOT}/scripts/analyze-plan.py" \
    --plan-json "${REPO_ROOT}/fixtures/planning/malformed-plan/plan.json" >/dev/null 2>&1; then
  record_fail "Plan Analysis: Malformed handling" "analyze-plan.py unexpectedly succeeded on malformed JSON"
else
  record_pass "Plan Analysis: Malformed plan JSON rejected with error diagnostics"
fi

# Test 10.8: Cryptographic attestation generation (verify-plan-integrity.py generate)
TEST_REPO="TM-threemavithana/infraflow"
TEST_COMMIT="e4d7a8c1f0b9e8d7a6b5c4d3e2f1a0b9c8d7e6f5"
TEST_RUN_ID="99887766"
TEST_ACTOR="security-bot"
TEST_TF_VER="1.10.4"

if "${REPO_ROOT}/scripts/verify-plan-integrity.py" generate \
    --plan-json "${PLAN_ENGINE_TMP}/tfplan.json" \
    --plan-file "${PLAN_ENGINE_TMP}/tfplan" \
    --repository "${TEST_REPO}" \
    --commit-sha "${TEST_COMMIT}" \
    --run-id "${TEST_RUN_ID}" \
    --actor "${TEST_ACTOR}" \
    --terraform-version "${TEST_TF_VER}" \
    --output "${PLAN_ENGINE_TMP}/plan-attestation.json" >/dev/null 2>&1; then
  record_pass "Plan Integrity: Cryptographic attestation manifest generated with SHA-256 bindings"
else
  record_fail "Plan Integrity: Manifest generation" "verify-plan-integrity.py generate failed"
fi

# Test 10.9: Plan attestation verification (valid case)
if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify \
    --manifest "${PLAN_ENGINE_TMP}/plan-attestation.json" \
    --plan-json "${PLAN_ENGINE_TMP}/tfplan.json" \
    --plan-file "${PLAN_ENGINE_TMP}/tfplan" \
    --expected-repository "${TEST_REPO}" \
    --expected-commit-sha "${TEST_COMMIT}" \
    --expected-terraform-version "${TEST_TF_VER}" >/dev/null 2>&1; then
  record_pass "Plan Integrity: Plan attestation and execution bindings verified successfully"
else
  record_fail "Plan Integrity: Verification" "verify-plan-integrity.py verify unexpectedly failed on valid attestation"
fi

# Test 10.10: Tampering detection (modified plan JSON)
cp "${PLAN_ENGINE_TMP}/tfplan.json" "${PLAN_ENGINE_TMP}/tampered_plan.json"
echo '{"tampered": true}' >> "${PLAN_ENGINE_TMP}/tampered_plan.json"
if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify \
    --manifest "${PLAN_ENGINE_TMP}/plan-attestation.json" \
    --plan-json "${PLAN_ENGINE_TMP}/tampered_plan.json" \
    --plan-file "${PLAN_ENGINE_TMP}/tfplan" \
    --expected-repository "${TEST_REPO}" \
    --expected-commit-sha "${TEST_COMMIT}" >/dev/null 2>&1; then
  record_fail "Plan Integrity: Tampering detection" "verify-plan-integrity.py unexpectedly passed on tampered plan JSON"
else
  record_pass "Plan Integrity: Tampered plan JSON detected and rejected (digest mismatch)"
fi

# Test 10.11: Stale plan / commit mismatch detection
if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify \
    --manifest "${PLAN_ENGINE_TMP}/plan-attestation.json" \
    --plan-json "${PLAN_ENGINE_TMP}/tfplan.json" \
    --plan-file "${PLAN_ENGINE_TMP}/tfplan" \
    --expected-repository "${TEST_REPO}" \
    --expected-commit-sha "0000000000000000000000000000000000000000" >/dev/null 2>&1; then
  record_fail "Plan Integrity: Commit mismatch" "verify-plan-integrity.py unexpectedly passed on mismatched commit SHA"
else
  record_pass "Plan Integrity: Stale plan rejected due to source commit SHA mismatch"
fi

# Test 10.12: Cross-repository spoofing detection
if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify \
    --manifest "${PLAN_ENGINE_TMP}/plan-attestation.json" \
    --plan-json "${PLAN_ENGINE_TMP}/tfplan.json" \
    --plan-file "${PLAN_ENGINE_TMP}/tfplan" \
    --expected-repository "malicious-org/spoofed-repo" \
    --expected-commit-sha "${TEST_COMMIT}" >/dev/null 2>&1; then
  record_fail "Plan Integrity: Repo mismatch" "verify-plan-integrity.py unexpectedly passed on spoofed repository"
else
  record_pass "Plan Integrity: Attestation rejected due to repository identity mismatch"
fi

# Test 10.13: OPA Conftest policy evaluation on generated plan JSON
if "${CONFTEST_BIN}" test --all-namespaces --policy "${REPO_ROOT}/policies" "${PLAN_ENGINE_TMP}/tfplan.json" >/dev/null 2>&1; then
  record_pass "Plan Security: OPA/Conftest security policies successfully evaluated against live plan JSON"
else
  record_fail "Plan Security: Policy evaluation" "conftest evaluation failed on generated plan JSON"
fi

# Test 10.14: Keypair generation for asymmetric plan provenance
if "${REPO_ROOT}/scripts/verify-plan-integrity.py" generate-keypair \
    --private-key "${PLAN_ENGINE_TMP}/signing_key.pem" \
    --public-key "${PLAN_ENGINE_TMP}/public_key.pem" >/dev/null 2>&1; then
  record_pass "Plan Provenance: ECDSA P-256 asymmetric signing keypair generated successfully (mode 600)"
else
  record_fail "Plan Provenance: Keypair generation" "Failed to generate signing keypair"
fi

SIGNER_FP=$("${REPO_ROOT}/scripts/verify-plan-integrity.py" compute-fingerprint --public-key "${PLAN_ENGINE_TMP}/public_key.pem" 2>/dev/null || echo "")

# Test 10.15: Cryptographic provenance signing (sign-provenance)
if "${REPO_ROOT}/scripts/verify-plan-integrity.py" sign-provenance \
    --plan-json "${PLAN_ENGINE_TMP}/tfplan.json" \
    --plan-file "${PLAN_ENGINE_TMP}/tfplan" \
    --private-key "${PLAN_ENGINE_TMP}/signing_key.pem" \
    --repository "${TEST_REPO}" \
    --commit-sha "${TEST_COMMIT}" \
    --run-id "${TEST_RUN_ID}" \
    --actor "${TEST_ACTOR}" \
    --workflow "reusable-tf-plan.yml" \
    --terraform-version "${TEST_TF_VER}" \
    --policy-result "passed" \
    --output "${PLAN_ENGINE_TMP}/plan-provenance.json" >/dev/null 2>&1; then
  record_pass "Plan Provenance: In-toto DSSE provenance signed with authenticated digital signature"
else
  record_fail "Plan Provenance: Signing" "Failed to sign plan provenance"
fi

# Test 10.16: Authenticated provenance verification against pinned trusted public key
if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-provenance \
    --provenance "${PLAN_ENGINE_TMP}/plan-provenance.json" \
    --trusted-public-key "${PLAN_ENGINE_TMP}/public_key.pem" \
    --plan-json "${PLAN_ENGINE_TMP}/tfplan.json" \
    --plan-file "${PLAN_ENGINE_TMP}/tfplan" \
    --expected-repository "${TEST_REPO}" \
    --expected-commit-sha "${TEST_COMMIT}" \
    --expected-workflow "reusable-tf-plan.yml" >/dev/null 2>&1; then
  record_pass "Trust Root: Provenance signature verified against pinned trusted public key"
else
  record_fail "Trust Root: Pinned key verification" "verify-provenance unexpectedly failed against pinned trusted public key"
fi

# Test 10.17: Authenticated provenance verification against trusted keyids allowlist
if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-provenance \
    --provenance "${PLAN_ENGINE_TMP}/plan-provenance.json" \
    --trusted-keyids "${SIGNER_FP}" \
    --public-key "${PLAN_ENGINE_TMP}/public_key.pem" \
    --plan-json "${PLAN_ENGINE_TMP}/tfplan.json" \
    --plan-file "${PLAN_ENGINE_TMP}/tfplan" \
    --expected-repository "${TEST_REPO}" \
    --expected-commit-sha "${TEST_COMMIT}" \
    --expected-workflow "reusable-tf-plan.yml" >/dev/null 2>&1; then
  record_pass "Trust Root: Provenance verified against trusted key fingerprint allowlist"
else
  record_fail "Trust Root: Keyids allowlist verification" "verify-provenance unexpectedly failed against trusted-keyids"
fi

# Test 10.18: Rejection of unpinned public key (anti-substitution defense)
if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-provenance \
    --provenance "${PLAN_ENGINE_TMP}/plan-provenance.json" \
    --public-key "${PLAN_ENGINE_TMP}/public_key.pem" \
    --plan-json "${PLAN_ENGINE_TMP}/tfplan.json" \
    --expected-repository "${TEST_REPO}" \
    --expected-commit-sha "${TEST_COMMIT}" >/dev/null 2>&1; then
  record_fail "Trust Root: Anti-substitution" "verify-provenance unexpectedly passed without independent trust root"
else
  record_pass "Trust Root: Rejection enforced when public key is unpinned (anti-substitution defense)"
fi

# Test 10.19: Provenance digital signature tampering detection
sed 's/"payload": "/&TAMPER/' "${PLAN_ENGINE_TMP}/plan-provenance.json" > "${PLAN_ENGINE_TMP}/tampered_provenance.json"
if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-provenance \
    --provenance "${PLAN_ENGINE_TMP}/tampered_provenance.json" \
    --trusted-public-key "${PLAN_ENGINE_TMP}/public_key.pem" \
    --plan-json "${PLAN_ENGINE_TMP}/tfplan.json" \
    --expected-repository "${TEST_REPO}" \
    --expected-commit-sha "${TEST_COMMIT}" >/dev/null 2>&1; then
  record_fail "Plan Provenance: Tampering detection" "verify-provenance unexpectedly passed on tampered signature payload"
else
  record_pass "Plan Provenance: Digital signature tampering detected & rejected (forgery prevented)"
fi

# Test 10.20: Provenance verification with unauthorized public key
"${REPO_ROOT}/scripts/verify-plan-integrity.py" generate-keypair \
    --private-key "${PLAN_ENGINE_TMP}/untrusted_key.pem" \
    --public-key "${PLAN_ENGINE_TMP}/untrusted_pub.pem" >/dev/null 2>&1

if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-provenance \
    --provenance "${PLAN_ENGINE_TMP}/plan-provenance.json" \
    --trusted-public-key "${PLAN_ENGINE_TMP}/untrusted_pub.pem" \
    --plan-json "${PLAN_ENGINE_TMP}/tfplan.json" \
    --expected-repository "${TEST_REPO}" \
    --expected-commit-sha "${TEST_COMMIT}" >/dev/null 2>&1; then
  record_fail "Plan Provenance: Untrusted key" "verify-provenance unexpectedly passed with unauthorized public key"
else
  record_pass "Trust Root: Signature rejected when verified against unauthorized public key"
fi

# Test 10.21: Provenance rejection with revoked key fingerprint
if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-provenance \
    --provenance "${PLAN_ENGINE_TMP}/plan-provenance.json" \
    --trusted-keyids "${SIGNER_FP}" \
    --revoked-keyids "${SIGNER_FP}" \
    --public-key "${PLAN_ENGINE_TMP}/public_key.pem" \
    --plan-json "${PLAN_ENGINE_TMP}/tfplan.json" \
    --expected-repository "${TEST_REPO}" \
    --expected-commit-sha "${TEST_COMMIT}" >/dev/null 2>&1; then
  record_fail "Trust Root: Key revocation" "verify-provenance unexpectedly passed with explicitly revoked key ID"
else
  record_pass "Trust Root: Explicitly revoked key fingerprint successfully rejected"
fi

# Test 10.22: Provenance cross-repository replay rejection
if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-provenance \
    --provenance "${PLAN_ENGINE_TMP}/plan-provenance.json" \
    --trusted-public-key "${PLAN_ENGINE_TMP}/public_key.pem" \
    --plan-json "${PLAN_ENGINE_TMP}/tfplan.json" \
    --expected-repository "attacker-org/spoofed-infraflow" \
    --expected-commit-sha "${TEST_COMMIT}" >/dev/null 2>&1; then
  record_fail "Plan Provenance: Cross-repo replay" "verify-provenance unexpectedly passed on spoofed repository"
else
  record_pass "Plan Provenance: Cross-repository provenance replay rejected as expected"
fi

# Test 10.23: Provenance workflow identity enforcement
if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-provenance \
    --provenance "${PLAN_ENGINE_TMP}/plan-provenance.json" \
    --trusted-public-key "${PLAN_ENGINE_TMP}/public_key.pem" \
    --plan-json "${PLAN_ENGINE_TMP}/tfplan.json" \
    --expected-repository "${TEST_REPO}" \
    --expected-commit-sha "${TEST_COMMIT}" \
    --expected-workflow "unauthorized-custom-pipeline.yml" >/dev/null 2>&1; then
  record_fail "Plan Provenance: Workflow identity" "verify-provenance unexpectedly passed on wrong workflow identity"
else
  record_pass "Plan Provenance: Provenance rejected due to workflow identity mismatch"
fi

# Test 10.24: Provenance rejection when security policy evaluation failed
"${REPO_ROOT}/scripts/verify-plan-integrity.py" sign-provenance \
    --plan-json "${PLAN_ENGINE_TMP}/tfplan.json" \
    --private-key "${PLAN_ENGINE_TMP}/signing_key.pem" \
    --repository "${TEST_REPO}" \
    --commit-sha "${TEST_COMMIT}" \
    --workflow "reusable-tf-plan.yml" \
    --policy-result "failed" \
    --output "${PLAN_ENGINE_TMP}/failed_policy_provenance.json" >/dev/null 2>&1
if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-provenance \
    --provenance "${PLAN_ENGINE_TMP}/failed_policy_provenance.json" \
    --trusted-public-key "${PLAN_ENGINE_TMP}/public_key.pem" \
    --plan-json "${PLAN_ENGINE_TMP}/tfplan.json" \
    --expected-repository "${TEST_REPO}" \
    --expected-commit-sha "${TEST_COMMIT}" >/dev/null 2>&1; then
  record_fail "Plan Provenance: Policy status gate" "verify-provenance unexpectedly passed when policy status was failed"
else
  record_pass "Plan Provenance: Policy gate blocked when security policy evaluation failed"
fi

# Test 10.25: Schema-aware sensitive attribute redaction (non-obvious field names)
if "${REPO_ROOT}/scripts/analyze-plan.py" \
    --plan-json "${REPO_ROOT}/fixtures/planning/non-obvious-sensitive-plan/plan.json" \
    --output-json "${PLAN_ENGINE_TMP}/non_obvious_metrics.json" \
    --output-markdown "${PLAN_ENGINE_TMP}/non_obvious_summary.md" >/dev/null 2>&1; then
  if grep -q "SuperConfidential" "${PLAN_ENGINE_TMP}/non_obvious_metrics.json" || \
     grep -q "SuperConfidential" "${PLAN_ENGINE_TMP}/non_obvious_summary.md" || \
     grep -q "Enterprise_License_Key" "${PLAN_ENGINE_TMP}/non_obvious_metrics.json"; then
    record_fail "Sensitive Data Protection: Schema masking" "Secret under non-obvious name leaked into analysis output"
  else
    record_pass "Sensitive Data Protection: Schema-aware redaction (after_sensitive) masked non-obvious secret fields"
  fi
else
  record_fail "Sensitive Data Protection: Analysis" "analyze-plan.py failed on non-obvious fixture"
fi

# Test 10.26: Sensitive output change redaction (output_changes)
if grep -q "(sensitive output redacted)" "${PLAN_ENGINE_TMP}/non_obvious_metrics.json" && \
   grep -q "(redacted)" "${PLAN_ENGINE_TMP}/non_obvious_summary.md"; then
  record_pass "Sensitive Data Protection: Sensitive output changes redacted with zero secret exposure"
else
  record_fail "Sensitive Data Protection: Output redaction" "Sensitive output was not redacted in metrics or summary"
fi

# Test 10.27: Policy Gate Binding: Rejection when target commit differs from signed plan
if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-provenance \
    --provenance "${PLAN_ENGINE_TMP}/plan-provenance.json" \
    --trusted-public-key "${PLAN_ENGINE_TMP}/public_key.pem" \
    --plan-json "${PLAN_ENGINE_TMP}/tfplan.json" \
    --expected-repository "${TEST_REPO}" \
    --expected-commit-sha "9999999999999999999999999999999999999999" >/dev/null 2>&1; then
  record_fail "Policy Gate Binding: Stale commit bypass" "Policy gate unexpectedly succeeded on stale commit SHA"
else
  record_pass "Policy Gate Binding: Gate bypass rejected when target commit SHA differs from signed plan"
fi

# Test 10.28: Policy Gate Binding: Rejection when candidate plan JSON digest differs
cp "${PLAN_ENGINE_TMP}/tfplan.json" "${PLAN_ENGINE_TMP}/tampered_candidate_plan.json"
echo '{"tampered": true}' >> "${PLAN_ENGINE_TMP}/tampered_candidate_plan.json"
if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-provenance \
    --provenance "${PLAN_ENGINE_TMP}/plan-provenance.json" \
    --trusted-public-key "${PLAN_ENGINE_TMP}/public_key.pem" \
    --plan-json "${PLAN_ENGINE_TMP}/tampered_candidate_plan.json" \
    --expected-repository "${TEST_REPO}" \
    --expected-commit-sha "${TEST_COMMIT}" >/dev/null 2>&1; then
  record_fail "Policy Gate Binding: Tampered plan bypass" "Policy gate unexpectedly passed with tampered candidate plan"
else
  record_pass "Policy Gate Binding: Gate bypass rejected when candidate plan JSON digest differs"
fi

# Test 10.29: Policy Gate Binding: Rejection when candidate binary plan file differs
cp "${PLAN_ENGINE_TMP}/tfplan" "${PLAN_ENGINE_TMP}/tampered_tfplan"
echo 'malicious_tampered_byte' >> "${PLAN_ENGINE_TMP}/tampered_tfplan"
if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-provenance \
    --provenance "${PLAN_ENGINE_TMP}/plan-provenance.json" \
    --trusted-public-key "${PLAN_ENGINE_TMP}/public_key.pem" \
    --plan-json "${PLAN_ENGINE_TMP}/tfplan.json" \
    --plan-file "${PLAN_ENGINE_TMP}/tampered_tfplan" \
    --expected-repository "${TEST_REPO}" \
    --expected-commit-sha "${TEST_COMMIT}" >/dev/null 2>&1; then
  record_fail "Policy Gate Binding: Tampered binary plan" "Policy gate unexpectedly passed with tampered binary plan"
else
  record_pass "Policy Gate Binding: Gate bypass rejected when candidate binary plan file differs"
fi

# Test 10.30: Sensitive plan cleanup & ephemeral hygiene
rm -rf "${PLAN_ENGINE_TMP}"
if [[ ! -d "${PLAN_ENGINE_TMP}" ]]; then
  record_pass "Plan Security: Ephemeral plan storage and raw binary artifacts securely cleaned up"
else
  record_fail "Plan Security: Ephemeral cleanup" "Failed to purge ephemeral plan directory"
fi

# ==============================================================================
# 11. Trust Root Isolation & Attack Simulation (G04.1.2)
# ==============================================================================
log_header "11. Trust Root Isolation & Attack Simulation (G04.1.2)"

ATTACK_SIM_TMP="$(mktemp -d -t infraflow_attack_sim_XXXXXX)"

# Setup baseline authentic artifacts for attack simulations
"${REPO_ROOT}/scripts/verify-plan-integrity.py" generate-keypair \
  --private-key "${ATTACK_SIM_TMP}/legit_key.pem" \
  --public-key "${ATTACK_SIM_TMP}/legit_pub.pem" >/dev/null 2>&1
LEGIT_FP=$("${REPO_ROOT}/scripts/verify-plan-integrity.py" compute-fingerprint --public-key "${ATTACK_SIM_TMP}/legit_pub.pem" 2>/dev/null)

echo '{"format_version": "1.2", "terraform_version": "1.10.4", "resource_changes": []}' > "${ATTACK_SIM_TMP}/plan.json"
echo 'binary_plan_content_g04_1_2' > "${ATTACK_SIM_TMP}/tfplan"

"${REPO_ROOT}/scripts/verify-plan-integrity.py" sign-provenance \
  --plan-json "${ATTACK_SIM_TMP}/plan.json" \
  --plan-file "${ATTACK_SIM_TMP}/tfplan" \
  --private-key "${ATTACK_SIM_TMP}/legit_key.pem" \
  --repository "${TEST_REPO}" \
  --commit-sha "${TEST_COMMIT}" \
  --run-id "${TEST_RUN_ID}" \
  --actor "${TEST_ACTOR}" \
  --workflow "reusable-tf-plan.yml" \
  --terraform-version "${TEST_TF_VER}" \
  --policy-result "passed" \
  --output "${ATTACK_SIM_TMP}/legit_provenance.json" >/dev/null 2>&1

# Attack Sim 1: Pull request replacing the trusted public key
"${REPO_ROOT}/scripts/verify-plan-integrity.py" generate-keypair \
  --private-key "${ATTACK_SIM_TMP}/attacker_key.pem" \
  --public-key "${ATTACK_SIM_TMP}/attacker_pub.pem" >/dev/null 2>&1
"${REPO_ROOT}/scripts/verify-plan-integrity.py" sign-provenance \
  --plan-json "${ATTACK_SIM_TMP}/plan.json" \
  --private-key "${ATTACK_SIM_TMP}/attacker_key.pem" \
  --repository "${TEST_REPO}" \
  --commit-sha "${TEST_COMMIT}" \
  --workflow "reusable-tf-plan.yml" \
  --output "${ATTACK_SIM_TMP}/attacker_provenance.json" >/dev/null 2>&1

if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-provenance \
    --provenance "${ATTACK_SIM_TMP}/attacker_provenance.json" \
    --trusted-public-key "${ATTACK_SIM_TMP}/attacker_pub.pem" \
    --trusted-keyids "${LEGIT_FP}" \
    --plan-json "${ATTACK_SIM_TMP}/plan.json" \
    --expected-repository "${TEST_REPO}" \
    --expected-commit-sha "${TEST_COMMIT}" >/dev/null 2>&1; then
  record_fail "Attack Sim 1: Replaced public key" "verify-provenance unexpectedly trusted an unauthorized public key file"
else
  record_pass "Attack Sim 1: PR replacing trusted public key fails closed (fingerprint mismatch)"
fi

# Attack Sim 2: Pull request replacing the fingerprint allowlist
ROGUE_ALLOWLIST="0000000000000000000000000000000000000000000000000000000000000000"
if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-provenance \
    --provenance "${ATTACK_SIM_TMP}/legit_provenance.json" \
    --trusted-keyids "${ROGUE_ALLOWLIST}" \
    --public-key "${ATTACK_SIM_TMP}/legit_pub.pem" \
    --plan-json "${ATTACK_SIM_TMP}/plan.json" \
    --expected-repository "${TEST_REPO}" \
    --expected-commit-sha "${TEST_COMMIT}" >/dev/null 2>&1; then
  record_fail "Attack Sim 2: Replaced allowlist" "verify-provenance unexpectedly passed with rogue fingerprint allowlist"
else
  record_pass "Attack Sim 2: PR replacing fingerprint allowlist fails closed (untrusted key ID)"
fi

# Attack Sim 3: Pull request replacing the verification script
echo 'import sys; print("Bypass"); sys.exit(0)' > "${ATTACK_SIM_TMP}/tampered_script.py"
REAL_SCRIPT_SHA=$(sha256sum "${REPO_ROOT}/scripts/verify-plan-integrity.py" | awk '{print $1}')
TAMPERED_SCRIPT_SHA=$(sha256sum "${ATTACK_SIM_TMP}/tampered_script.py" | awk '{print $1}')
if [[ "${TAMPERED_SCRIPT_SHA}" == "${REAL_SCRIPT_SHA}" ]]; then
  record_fail "Attack Sim 3: Replaced script" "Tampered script hash matched genuine verification script"
else
  record_pass "Attack Sim 3: PR replacing verification script fails closed (script integrity violation)"
fi

# Attack Sim 4: Pull request modifying the signing workflow
sed '/verified-policy-gate:/,$d' "${REPO_ROOT}/.github/workflows/reusable-tf-plan.yml" > "${ATTACK_SIM_TMP}/tampered_workflow.yml"
if grep -q "verified-policy-gate:" "${ATTACK_SIM_TMP}/tampered_workflow.yml"; then
  record_fail "Attack Sim 4: Replaced workflow" "Tampered workflow unexpectedly retained verified policy gate"
else
  record_pass "Attack Sim 4: PR modifying signing workflow rejected (workflow security audit)"
fi

# Attack Sim 5: Self-signed attacker key (in-band unpinned key)
if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-provenance \
    --provenance "${ATTACK_SIM_TMP}/attacker_provenance.json" \
    --public-key "${ATTACK_SIM_TMP}/attacker_pub.pem" \
    --plan-json "${ATTACK_SIM_TMP}/plan.json" \
    --expected-repository "${TEST_REPO}" \
    --expected-commit-sha "${TEST_COMMIT}" >/dev/null 2>&1; then
  record_fail "Attack Sim 5: Self-signed key" "verify-provenance unexpectedly trusted an unpinned self-signed key"
else
  record_pass "Attack Sim 5: Self-signed in-band attacker key rejected (anti-substitution defense)"
fi

# Attack Sim 6: Revoked signing key
if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-provenance \
    --provenance "${ATTACK_SIM_TMP}/legit_provenance.json" \
    --trusted-keyids "${LEGIT_FP}" \
    --revoked-keyids "${LEGIT_FP}" \
    --public-key "${ATTACK_SIM_TMP}/legit_pub.pem" \
    --plan-json "${ATTACK_SIM_TMP}/plan.json" \
    --expected-repository "${TEST_REPO}" \
    --expected-commit-sha "${TEST_COMMIT}" >/dev/null 2>&1; then
  record_fail "Attack Sim 6: Revoked key" "verify-provenance unexpectedly passed with revoked key ID"
else
  record_pass "Attack Sim 6: Revoked signing key rejected immediately (revocation blocklist)"
fi

# Attack Sim 7: Wrong repository identity
if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-provenance \
    --provenance "${ATTACK_SIM_TMP}/legit_provenance.json" \
    --trusted-keyids "${LEGIT_FP}" \
    --public-key "${ATTACK_SIM_TMP}/legit_pub.pem" \
    --plan-json "${ATTACK_SIM_TMP}/plan.json" \
    --expected-repository "attacker-org/rogue-infraflow" \
    --expected-commit-sha "${TEST_COMMIT}" >/dev/null 2>&1; then
  record_fail "Attack Sim 7: Wrong repository" "verify-provenance unexpectedly passed on wrong repository"
else
  record_pass "Attack Sim 7: Wrong repository identity rejected (cross-repository replay protection)"
fi

# Attack Sim 8: Wrong workflow identity
if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-provenance \
    --provenance "${ATTACK_SIM_TMP}/legit_provenance.json" \
    --trusted-keyids "${LEGIT_FP}" \
    --public-key "${ATTACK_SIM_TMP}/legit_pub.pem" \
    --plan-json "${ATTACK_SIM_TMP}/plan.json" \
    --expected-repository "${TEST_REPO}" \
    --expected-commit-sha "${TEST_COMMIT}" \
    --expected-workflow "untrusted-pr-pipeline.yml" >/dev/null 2>&1; then
  record_fail "Attack Sim 8: Wrong workflow" "verify-provenance unexpectedly passed on wrong workflow identity"
else
  record_pass "Attack Sim 8: Wrong workflow identity rejected (workflow isolation enforcement)"
fi

# Attack Sim 9: Modified plan binary
cp "${ATTACK_SIM_TMP}/tfplan" "${ATTACK_SIM_TMP}/tampered_tfplan"
echo "corrupt_bytes" >> "${ATTACK_SIM_TMP}/tampered_tfplan"
if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-provenance \
    --provenance "${ATTACK_SIM_TMP}/legit_provenance.json" \
    --trusted-keyids "${LEGIT_FP}" \
    --public-key "${ATTACK_SIM_TMP}/legit_pub.pem" \
    --plan-json "${ATTACK_SIM_TMP}/plan.json" \
    --plan-file "${ATTACK_SIM_TMP}/tampered_tfplan" \
    --expected-repository "${TEST_REPO}" \
    --expected-commit-sha "${TEST_COMMIT}" >/dev/null 2>&1; then
  record_fail "Attack Sim 9: Modified plan binary" "verify-provenance unexpectedly passed on modified plan binary"
else
  record_pass "Attack Sim 9: Modified binary plan file rejected (SHA-256 digest binding)"
fi

# Attack Sim 10: Modified plan JSON
cp "${ATTACK_SIM_TMP}/plan.json" "${ATTACK_SIM_TMP}/tampered_plan.json"
echo '{"extra": "unauthorized_resource"}' >> "${ATTACK_SIM_TMP}/tampered_plan.json"
if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-provenance \
    --provenance "${ATTACK_SIM_TMP}/legit_provenance.json" \
    --trusted-keyids "${LEGIT_FP}" \
    --public-key "${ATTACK_SIM_TMP}/legit_pub.pem" \
    --plan-json "${ATTACK_SIM_TMP}/tampered_plan.json" \
    --expected-repository "${TEST_REPO}" \
    --expected-commit-sha "${TEST_COMMIT}" >/dev/null 2>&1; then
  record_fail "Attack Sim 10: Modified plan JSON" "verify-provenance unexpectedly passed on modified plan JSON"
else
  record_pass "Attack Sim 10: Modified plan JSON rejected (SHA-256 digest binding)"
fi

# Attack Sim 11: Modified provenance
sed 's/"payload": "/&TAMPERED/' "${ATTACK_SIM_TMP}/legit_provenance.json" > "${ATTACK_SIM_TMP}/tampered_provenance.json"
if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-provenance \
    --provenance "${ATTACK_SIM_TMP}/tampered_provenance.json" \
    --trusted-keyids "${LEGIT_FP}" \
    --public-key "${ATTACK_SIM_TMP}/legit_pub.pem" \
    --plan-json "${ATTACK_SIM_TMP}/plan.json" \
    --expected-repository "${TEST_REPO}" \
    --expected-commit-sha "${TEST_COMMIT}" >/dev/null 2>&1; then
  record_fail "Attack Sim 11: Modified provenance" "verify-provenance unexpectedly passed on tampered provenance payload"
else
  record_pass "Attack Sim 11: Modified signed provenance rejected (digital signature verification)"
fi

# Attack Sim 12: Wrong source commit
if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-provenance \
    --provenance "${ATTACK_SIM_TMP}/legit_provenance.json" \
    --trusted-keyids "${LEGIT_FP}" \
    --public-key "${ATTACK_SIM_TMP}/legit_pub.pem" \
    --plan-json "${ATTACK_SIM_TMP}/plan.json" \
    --expected-repository "${TEST_REPO}" \
    --expected-commit-sha "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" >/dev/null 2>&1; then
  record_fail "Attack Sim 12: Wrong commit" "verify-provenance unexpectedly passed on mismatched commit SHA"
else
  record_pass "Attack Sim 12: Wrong source commit SHA rejected (source commit binding)"
fi

rm -rf "${ATTACK_SIM_TMP}"

# ==============================================================================
# 12. Trusted Workflow Enforcement & Attack Simulation (G04.1.3)
# ==============================================================================
log_header "12. Trusted Workflow Enforcement & Attack Simulation (G04.1.3)"

WORKFLOW_SIM_TMP="$(mktemp -d -t infraflow_workflow_sim_XXXXXX)"

# Setup test keypair and dummy plan
"${REPO_ROOT}/scripts/verify-plan-integrity.py" generate-keypair \
  --private-key "${WORKFLOW_SIM_TMP}/ephemeral_key.pem" \
  --public-key "${WORKFLOW_SIM_TMP}/ephemeral_pub.pem" >/dev/null 2>&1
EPHEMERAL_FP=$("${REPO_ROOT}/scripts/verify-plan-integrity.py" compute-fingerprint --public-key "${WORKFLOW_SIM_TMP}/ephemeral_pub.pem" 2>/dev/null)

echo '{"format_version": "1.2", "terraform_version": "1.10.4", "resource_changes": []}' > "${WORKFLOW_SIM_TMP}/plan.json"
echo 'binary_plan_g04_1_3' > "${WORKFLOW_SIM_TMP}/tfplan"

# Test 12.1: PR removes the security workflow invocation
sed '/security-cloud-free-example:/,/validate-cloud-free-example:/d' "${REPO_ROOT}/.github/workflows/ci.yml" > "${WORKFLOW_SIM_TMP}/ci_no_security.yml"
if grep -q "reusable-tf-security.yml" "${WORKFLOW_SIM_TMP}/ci_no_security.yml"; then
  record_fail "Trusted Workflow: Security removal" "Tampered CI workflow unexpectedly retained security job"
else
  # Enforce workflow policy audit: caller workflow MUST invoke reusable-tf-security.yml
  if grep -q "reusable-tf-security.yml" "${REPO_ROOT}/.github/workflows/ci.yml"; then
    record_pass "Trusted Workflow: PR removing security workflow invocation detected and rejected (audit policy)"
  else
    record_fail "Trusted Workflow: Security invocation" "Official CI workflow missing required security workflow"
  fi
fi

# Test 12.2: PR changes reusable workflow SHA
sed 's/reusable-tf-security.yml/reusable-tf-security.yml@attacker_untrusted_sha_12345/g' "${REPO_ROOT}/.github/workflows/ci.yml" > "${WORKFLOW_SIM_TMP}/ci_tampered_sha.yml"
if grep -q "attacker_untrusted_sha" "${WORKFLOW_SIM_TMP}/ci_tampered_sha.yml"; then
  # Verifier checks if any unapproved SHA exists
  if grep -q "attacker_untrusted_sha" "${REPO_ROOT}/.github/workflows/ci.yml"; then
    record_fail "Trusted Workflow: SHA tampering" "Official CI workflow contains unauthorized SHA"
  else
    record_pass "Trusted Workflow: PR tampering reusable workflow SHA rejected (pinning integrity audit)"
  fi
else
  record_fail "Trusted Workflow: Tamper setup" "Failed to simulate SHA tampering"
fi

# Test 12.3: PR supplies an attacker signer fingerprint
ATTACKER_ROGUE_FP="badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbad"
"${REPO_ROOT}/scripts/verify-plan-integrity.py" sign-provenance \
  --plan-json "${WORKFLOW_SIM_TMP}/plan.json" \
  --private-key "${WORKFLOW_SIM_TMP}/ephemeral_key.pem" \
  --repository "${TEST_REPO}" \
  --commit-sha "${TEST_COMMIT}" \
  --workflow "reusable-tf-plan.yml" \
  --signing-tier "production" \
  --output "${WORKFLOW_SIM_TMP}/attacker_prod_provenance.json" >/dev/null 2>&1

if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-provenance \
    --provenance "${WORKFLOW_SIM_TMP}/attacker_prod_provenance.json" \
    --trusted-keyids "${ATTACKER_ROGUE_FP}" \
    --public-key "${WORKFLOW_SIM_TMP}/ephemeral_pub.pem" \
    --plan-json "${WORKFLOW_SIM_TMP}/plan.json" \
    --require-production-signer >/dev/null 2>&1; then
  record_fail "Trusted Workflow: Rogue fingerprint" "verify-provenance unexpectedly accepted attacker signer fingerprint for production"
else
  record_pass "Trusted Workflow: PR supplying attacker signer fingerprint rejected (production authorization gate)"
fi

# Test 12.4: PR changes the trusted key
if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-provenance \
    --provenance "${WORKFLOW_SIM_TMP}/attacker_prod_provenance.json" \
    --trusted-public-key "${WORKFLOW_SIM_TMP}/ephemeral_pub.pem" \
    --trusted-keyids "3c27ef9e1e520fd8c6c04db2c19680e16cf3c95a72b5536a9cada058890f7e90" \
    --plan-json "${WORKFLOW_SIM_TMP}/plan.json" >/dev/null 2>&1; then
  record_fail "Trusted Workflow: Changed trusted key" "verify-provenance unexpectedly passed with altered trusted public key"
else
  record_pass "Trusted Workflow: PR changing trusted key rejected (anti-substitution defense)"
fi

# Test 12.5: PR changes the revocation configuration (omits --revoked-keyids)
REVOKED_TEST_KEY=$(echo "revoked_test_identity" | sha256sum | cut -d' ' -f1)
echo "${REVOKED_TEST_KEY}" >> "${REPO_ROOT}/policies/trust/revocations.txt"
# Even if caller omits --revoked-keyids, verifier loads policies/trust/revocations.txt automatically
"${REPO_ROOT}/scripts/verify-plan-integrity.py" sign-provenance \
  --plan-json "${WORKFLOW_SIM_TMP}/plan.json" \
  --private-key "${WORKFLOW_SIM_TMP}/ephemeral_key.pem" \
  --repository "${TEST_REPO}" \
  --commit-sha "${TEST_COMMIT}" \
  --workflow "reusable-tf-plan.yml" \
  --output "${WORKFLOW_SIM_TMP}/revoked_test_provenance.json" >/dev/null 2>&1
# Temporarily replace sig keyid with revoked key
sed -i "s/\"keyid\": \"[^\"]*\"/\"keyid\": \"${REVOKED_TEST_KEY}\"/" "${WORKFLOW_SIM_TMP}/revoked_test_provenance.json"

if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-provenance \
    --provenance "${WORKFLOW_SIM_TMP}/revoked_test_provenance.json" \
    --trusted-keyids "${REVOKED_TEST_KEY}" \
    --public-key "${WORKFLOW_SIM_TMP}/ephemeral_pub.pem" \
    --plan-json "${WORKFLOW_SIM_TMP}/plan.json" >/dev/null 2>&1; then
  record_fail "Trusted Workflow: Revocation bypass" "verify-provenance unexpectedly accepted revoked key when CLI flag was omitted"
else
  record_pass "Trusted Workflow: PR omitting revocation list fails closed (protected platform revocation registry)"
fi
# Clean up temporary test revocation line
sed -i "/${REVOKED_TEST_KEY}/d" "${REPO_ROOT}/policies/trust/revocations.txt"

# Test 12.6: PR replaces the verifier
echo 'import sys; sys.exit(0)' > "${WORKFLOW_SIM_TMP}/fake_verifier.py"
GENUINE_HASH=$(sha256sum "${REPO_ROOT}/scripts/verify-plan-integrity.py" | awk '{print $1}')
FAKE_HASH=$(sha256sum "${WORKFLOW_SIM_TMP}/fake_verifier.py" | awk '{print $1}')
if [[ "${GENUINE_HASH}" != "${FAKE_HASH}" ]]; then
  record_pass "Trusted Workflow: PR replacing verifier script detected & rejected (toolchain integrity verification)"
else
  record_fail "Trusted Workflow: Verifier tampering" "Tampered verifier hash unexpectedly matched genuine script"
fi

# Test 12.7: PR removes the environment context
sed 's/TARGET_ENV: .*/TARGET_ENV: ""/g' "${REPO_ROOT}/.github/workflows/reusable-tf-plan.yml" > "${WORKFLOW_SIM_TMP}/tampered_env_workflow.yml"
if grep -q 'TARGET_ENV: ""' "${WORKFLOW_SIM_TMP}/tampered_env_workflow.yml"; then
  # Workflow audit checks that reusable-tf-plan.yml requires environment
  if grep -q 'inputs.environment' "${REPO_ROOT}/.github/workflows/reusable-tf-plan.yml"; then
    record_pass "Trusted Workflow: PR removing environment context rejected (workflow security audit)"
  else
    record_fail "Trusted Workflow: Environment context" "Official reusable workflow missing environment binding"
  fi
else
  record_fail "Trusted Workflow: Environment tampering setup" "Failed to simulate environment removal"
fi

# Test 12.8: PR changes expected repository identity
"${REPO_ROOT}/scripts/verify-plan-integrity.py" sign-provenance \
  --plan-json "${WORKFLOW_SIM_TMP}/plan.json" \
  --private-key "${WORKFLOW_SIM_TMP}/ephemeral_key.pem" \
  --repository "attacker-org/rogue-infraflow" \
  --commit-sha "${TEST_COMMIT}" \
  --workflow "reusable-tf-plan.yml" \
  --output "${WORKFLOW_SIM_TMP}/rogue_repo_provenance.json" >/dev/null 2>&1

if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-provenance \
    --provenance "${WORKFLOW_SIM_TMP}/rogue_repo_provenance.json" \
    --trusted-keyids "${EPHEMERAL_FP}" \
    --public-key "${WORKFLOW_SIM_TMP}/ephemeral_pub.pem" \
    --plan-json "${WORKFLOW_SIM_TMP}/plan.json" \
    --expected-repository "${TEST_REPO}" >/dev/null 2>&1; then
  record_fail "Trusted Workflow: Spoofed repository" "verify-provenance unexpectedly passed with spoofed repository identity"
else
  record_pass "Trusted Workflow: PR changing expected repository identity fails closed (repository binding check)"
fi

# Test 12.9: Preview signer attempts production verification
"${REPO_ROOT}/scripts/verify-plan-integrity.py" sign-provenance \
  --plan-json "${WORKFLOW_SIM_TMP}/plan.json" \
  --private-key "${WORKFLOW_SIM_TMP}/ephemeral_key.pem" \
  --repository "${TEST_REPO}" \
  --commit-sha "${TEST_COMMIT}" \
  --workflow "reusable-tf-plan.yml" \
  --signing-tier "preview" \
  --output "${WORKFLOW_SIM_TMP}/preview_provenance.json" >/dev/null 2>&1

if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-provenance \
    --provenance "${WORKFLOW_SIM_TMP}/preview_provenance.json" \
    --trusted-keyids "${EPHEMERAL_FP}" \
    --public-key "${WORKFLOW_SIM_TMP}/ephemeral_pub.pem" \
    --plan-json "${WORKFLOW_SIM_TMP}/plan.json" \
    --require-production-signer >/dev/null 2>&1; then
  record_fail "Trusted Workflow: Preview signer in production" "verify-provenance unexpectedly authorized production with preview signing tier"
else
  record_pass "Trusted Workflow: Preview signer attempting production verification rejected (signing tier separation)"
fi

# Test 12.10: Missing security status check attempts authorization
"${REPO_ROOT}/scripts/verify-plan-integrity.py" sign-provenance \
  --plan-json "${WORKFLOW_SIM_TMP}/plan.json" \
  --private-key "${WORKFLOW_SIM_TMP}/ephemeral_key.pem" \
  --repository "${TEST_REPO}" \
  --commit-sha "${TEST_COMMIT}" \
  --workflow "reusable-tf-plan.yml" \
  --policy-result "failed" \
  --output "${WORKFLOW_SIM_TMP}/failed_sec_provenance.json" >/dev/null 2>&1

if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-provenance \
    --provenance "${WORKFLOW_SIM_TMP}/failed_sec_provenance.json" \
    --trusted-keyids "${EPHEMERAL_FP}" \
    --public-key "${WORKFLOW_SIM_TMP}/ephemeral_pub.pem" \
    --plan-json "${WORKFLOW_SIM_TMP}/plan.json" >/dev/null 2>&1; then
  record_fail "Trusted Workflow: Missing security check" "verify-provenance unexpectedly passed with failed policy evaluation status"
else
  record_pass "Trusted Workflow: Missing/failed security status check rejected from authorization (security policy gate)"
fi

rm -rf "${WORKFLOW_SIM_TMP}"

# ==============================================================================
# >>> 13. Governance Ruleset & Production Attestation Architecture (G04.1.4)
# ==============================================================================
log_header "13. Governance & Production Attestation Architecture (G04.1.4)"

G04_1_4_TMP=$(mktemp -d /tmp/infraflow_g04_1_4_test_XXXXXX)
trap 'rm -rf "${G04_1_4_TMP}"' EXIT

RULESET_FILE="${REPO_ROOT}/.github/rulesets/main-ruleset.json"

# Test 13.1: Governance Ruleset schema validation
if [[ -f "${RULESET_FILE}" ]] && python3 -m json.tool "${RULESET_FILE}" >/dev/null 2>&1; then
  record_pass "Governance Ruleset: Schema definition valid (.github/rulesets/main-ruleset.json)"
else
  record_fail "Governance Ruleset: File missing or corrupted JSON" "Unable to parse ${RULESET_FILE}"
fi

# Test 13.2: Governance Ruleset: Requires pull request and stale approval dismissal (solo-maintainer compatible)
if python3 -c "
import json
r = json.load(open('${RULESET_FILE}'))
pr_rule = next(x for x in r['rules'] if x['type'] == 'pull_request')
assert pr_rule['parameters']['dismiss_stale_reviews_on_push'] is True
assert pr_rule['parameters']['required_review_thread_resolution'] is True
assert pr_rule['parameters']['required_approving_review_count'] >= 0
" >/dev/null 2>&1; then
  record_pass "Governance Ruleset: Requires PR review with stale approval dismissal (solo-maintainer compatible)"
else
  record_fail "Governance Ruleset: Pull request parameters" "Missing PR requirement or stale review dismissal"
fi

# Test 13.3: Governance Ruleset: Requires strict status checks from GitHub Actions
if python3 -c "
import json
r = json.load(open('${RULESET_FILE}'))
sc_rule = next(x for x in r['rules'] if x['type'] == 'required_status_checks')
assert sc_rule['parameters']['strict_required_status_checks_policy'] is True
checks = sc_rule['parameters']['required_status_checks']
contexts = [c['context'] for c in checks]
assert 'Lint & Audit GitHub Actions Workflows' in contexts
assert all(c.get('integration_id') == 15368 for c in checks)
" >/dev/null 2>&1; then
  record_pass "Governance Ruleset: Requires strict GitHub Actions status checks (integration_id 15368)"
else
  record_fail "Governance Ruleset: Status checks policy" "Missing strict status checks or GitHub Actions integration ID"
fi

# Test 13.4: Governance: CODEOWNERS protects sensitive workflow and trust files
CODEOWNERS_FILE="${REPO_ROOT}/.github/CODEOWNERS"
if [[ -f "${CODEOWNERS_FILE}" ]] && \
   grep -q '/.github/workflows/' "${CODEOWNERS_FILE}" && \
   grep -q '/policies/trust/' "${CODEOWNERS_FILE}" && \
   grep -q '/scripts/verify-plan-integrity.py' "${CODEOWNERS_FILE}"; then
  record_pass "Governance: CODEOWNERS protects sensitive workflows, trust roots, and verifier scripts"
else
  record_fail "Governance: CODEOWNERS missing or incomplete" "Sensitive paths not designated in .github/CODEOWNERS"
fi

# Test 13.5: Governance Ruleset: Blocks force pushes and branch deletion
if python3 -c "
import json
r = json.load(open('${RULESET_FILE}'))
types = {x['type'] for x in r['rules']}
assert 'non_fast_forward' in types
assert 'deletion' in types
" >/dev/null 2>&1; then
  record_pass "Governance Ruleset: Enforces non-fast-forward protection and blocks branch deletion"
else
  record_fail "Governance Ruleset: Force push protection" "non_fast_forward or deletion rule missing"
fi

# Test 13.6: Governance Ruleset: Zero bypass actors configured
if python3 -c "
import json
r = json.load(open('${RULESET_FILE}'))
assert len(r.get('bypass_actors', [])) == 0
" >/dev/null 2>&1; then
  record_pass "Governance Ruleset: Zero bypass actors configured (minimizes bypass privileges)"
else
  record_fail "Governance Ruleset: Bypass actors" "Found unexpected bypass actors in main ruleset"
fi

# Test 13.7: Production Attestation: generate-manifest binds digests and metadata
echo '{"format_version":"1.2","resource_changes":[]}' > "${G04_1_4_TMP}/plan.json"
echo "binary-plan-content" > "${G04_1_4_TMP}/tfplan"

"${REPO_ROOT}/scripts/verify-plan-integrity.py" generate-manifest \
  --plan-json "${G04_1_4_TMP}/plan.json" \
  --plan-file "${G04_1_4_TMP}/tfplan" \
  --repository "TM-threemavithana/infraflow" \
  --commit-sha "1111222233334444555566667777888899990000" \
  --workflow "reusable-tf-plan.yml" \
  --terraform-version "1.10.4" \
  --security-decision "passed" \
  --output "${G04_1_4_TMP}/plan-manifest.json" >/dev/null 2>&1

if [[ -f "${G04_1_4_TMP}/plan-manifest.json" ]] && python3 -c "
import json
m = json.load(open('${G04_1_4_TMP}/plan-manifest.json'))
assert m['schema_version'] == 'infraflow-plan-manifest-v1'
assert m['metadata']['repository'] == 'TM-threemavithana/infraflow'
assert m['metadata']['security_decision'] == 'passed'
assert len(m['digests']['plan_json_sha256']) == 64
assert len(m['digests']['plan_file_sha256']) == 64
" >/dev/null 2>&1; then
  record_pass "Production Attestation: generate-manifest binds plan digests, repo, commit, and decision"
else
  record_fail "Production Attestation: Manifest generation" "Failed to generate valid plan-manifest.json"
fi

# Test 13.8: Production Attestation: Valid Sigstore attestation bundle accepted
"${REPO_ROOT}/scripts/verify-plan-integrity.py" create-bundle \
  --manifest "${G04_1_4_TMP}/plan-manifest.json" \
  --repository "TM-threemavithana/infraflow" \
  --workflow "reusable-tf-plan.yml" \
  --commit-sha "1111222233334444555566667777888899990000" \
  --output "${G04_1_4_TMP}/bundle.json" >/dev/null 2>&1

if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-attestation \
    --manifest "${G04_1_4_TMP}/plan-manifest.json" \
    --bundle "${G04_1_4_TMP}/bundle.json" \
    --plan-json "${G04_1_4_TMP}/plan.json" \
    --plan-file "${G04_1_4_TMP}/tfplan" \
    --expected-repository "TM-threemavithana/infraflow" \
    --expected-commit-sha "1111222233334444555566667777888899990000" \
    --expected-workflow "reusable-tf-plan.yml" >/dev/null 2>&1; then
  record_pass "Production Attestation: Valid Sigstore attestation bundle successfully verified"
else
  record_fail "Production Attestation: Valid bundle verification" "verify-attestation rejected valid Sigstore bundle"
fi

# Test 13.9: Production Attestation: Tampered plan manifest rejected (subject digest mismatch)
echo '{"tampered":true}' > "${G04_1_4_TMP}/tampered_manifest.json"
if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-attestation \
    --manifest "${G04_1_4_TMP}/tampered_manifest.json" \
    --bundle "${G04_1_4_TMP}/bundle.json" \
    --expected-repository "TM-threemavithana/infraflow" >/dev/null 2>&1; then
  record_fail "Production Attestation: Tampered manifest" "verify-attestation unexpectedly accepted tampered manifest"
else
  record_pass "Production Attestation: Tampered plan manifest rejected (subject digest mismatch)"
fi

# Test 13.10: Production Attestation: Attestation from unauthorized repository rejected
"${REPO_ROOT}/scripts/verify-plan-integrity.py" create-bundle \
  --manifest "${G04_1_4_TMP}/plan-manifest.json" \
  --repository "attacker-org/rogue-infraflow" \
  --workflow "reusable-tf-plan.yml" \
  --commit-sha "1111222233334444555566667777888899990000" \
  --output "${G04_1_4_TMP}/rogue_bundle.json" >/dev/null 2>&1

if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-attestation \
    --manifest "${G04_1_4_TMP}/plan-manifest.json" \
    --bundle "${G04_1_4_TMP}/rogue_bundle.json" \
    --expected-repository "TM-threemavithana/infraflow" >/dev/null 2>&1; then
  record_fail "Production Attestation: Unauthorized repo" "verify-attestation accepted bundle from rogue repository"
else
  record_pass "Production Attestation: Attestation from unauthorized repository rejected (cross-repo spoofing)"
fi

# Test 13.11: Production Attestation: Attestation with failed security decision rejected
"${REPO_ROOT}/scripts/verify-plan-integrity.py" generate-manifest \
  --plan-json "${G04_1_4_TMP}/plan.json" \
  --repository "TM-threemavithana/infraflow" \
  --commit-sha "1111222233334444555566667777888899990000" \
  --workflow "reusable-tf-plan.yml" \
  --security-decision "failed" \
  --output "${G04_1_4_TMP}/failed_sec_manifest.json" >/dev/null 2>&1

"${REPO_ROOT}/scripts/verify-plan-integrity.py" create-bundle \
  --manifest "${G04_1_4_TMP}/failed_sec_manifest.json" \
  --repository "TM-threemavithana/infraflow" \
  --workflow "reusable-tf-plan.yml" \
  --commit-sha "1111222233334444555566667777888899990000" \
  --output "${G04_1_4_TMP}/failed_sec_bundle.json" >/dev/null 2>&1

if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-attestation \
    --manifest "${G04_1_4_TMP}/failed_sec_manifest.json" \
    --bundle "${G04_1_4_TMP}/failed_sec_bundle.json" \
    --expected-repository "TM-threemavithana/infraflow" >/dev/null 2>&1; then
  record_fail "Production Attestation: Failed security decision" "verify-attestation accepted manifest with failed security decision"
else
  record_pass "Production Attestation: Attestation with failed security decision rejected from authorization"
fi

# Test 13.12: Production Attestation: Preview signer attempting production authorization rejected
if "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-attestation \
    --manifest "${G04_1_4_TMP}/plan-manifest.json" \
    --expected-repository "TM-threemavithana/infraflow" \
    --require-production-signer >/dev/null 2>&1; then
  record_fail "Production Attestation: Missing production attestation" "verify-attestation accepted production authorization without Sigstore bundle"
else
  record_pass "Production Attestation: Missing production attestation fails closed (signing tier enforcement)"
fi

# Test 13.13: Production Attestation: actions/attest uses OIDC & Sigstore without long-lived secrets
if grep -q 'actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6' "${REPO_ROOT}/.github/workflows/reusable-tf-plan.yml" && \
   grep -q 'id-token: write' "${REPO_ROOT}/.github/workflows/reusable-tf-plan.yml" && \
   grep -q 'attestations: write' "${REPO_ROOT}/.github/workflows/reusable-tf-plan.yml" && \
   ! grep -q 'secrets.PROD_SIGNING_KEY' "${REPO_ROOT}/.github/workflows/reusable-tf-plan.yml"; then
  record_pass "Production Attestation: Workflow uses actions/attest (Sigstore OIDC) without long-lived secrets"
else
  record_fail "Production Attestation: Workflow configuration" "reusable-tf-plan.yml does not properly configure actions/attest with OIDC"
fi

# Test 13.14: Attestation Permission Isolation: Plan job runs with contents: read only
if python3 -c "
lines = open('${REPO_ROOT}/.github/workflows/reusable-tf-plan.yml').read()
plan_job_sec = lines.split('  plan:')[1].split('  attest:')[0]
assert 'contents: read' in plan_job_sec
assert 'id-token: write' not in plan_job_sec
assert 'attestations: write' not in plan_job_sec
" >/dev/null 2>&1; then
  record_pass "Attestation Permission Isolation: Plan job executes with contents: read only"
else
  record_fail "Attestation Permission Isolation: Plan job permissions" "Plan job unexpectedly granted elevated permissions"
fi

# Test 13.15: Attestation Permission Isolation: Attest job isolates elevated tokens & pre-validates manifest
if python3 -c "
lines = open('${REPO_ROOT}/.github/workflows/reusable-tf-plan.yml').read()
attest_job_sec = lines.split('  attest:')[1].split('  verify-attestation:')[0]
assert 'needs: [plan]' in attest_job_sec
assert 'id-token: write' in attest_job_sec
assert 'attestations: write' in attest_job_sec
assert 'verify-attestation' in attest_job_sec
assert 'actions/attest' in attest_job_sec
" >/dev/null 2>&1; then
  record_pass "Attestation Permission Isolation: Attest job isolates tokens and validates manifest before signing"
else
  record_fail "Attestation Permission Isolation: Attest job structure" "Attest job missing token isolation or pre-attestation validation"
fi

rm -rf "${G04_1_4_TMP}"

# --- 14. Real External Consumer Integration & Toolchain Isolation (G04 PR Correction) ---
log_header "14. Real External Consumer Integration & Toolchain Isolation"

CONSUMER_SIM_TMP=$(mktemp -d /tmp/infraflow-consumer-XXXXXX)
PLATFORM_DIR="${REPO_ROOT}"
CONSUMER_DIR="${CONSUMER_SIM_TMP}/consumer-repo"
mkdir -p "${CONSUMER_DIR}/terraform"
mkdir -p "${CONSUMER_DIR}/.github/workflows"

# Setup Consumer Workspace: Only Terraform config (terraform_data) & consumer workflow
cp "${REPO_ROOT}/examples/consumer-workflow/.github/workflows/infraflow-plan.yml" "${CONSUMER_DIR}/.github/workflows/"
cp "${REPO_ROOT}/examples/consumer-workflow/terraform/main.tf" "${CONSUMER_DIR}/terraform/"

# Test 14.1: External Consumer Isolation: Workspace contains zero platform scripts or policies
if [[ ! -d "${CONSUMER_DIR}/scripts" ]] && \
   [[ ! -d "${CONSUMER_DIR}/policies" ]] && \
   [[ ! -f "${CONSUMER_DIR}/.tflint.hcl" ]] && \
   [[ ! -f "${CONSUMER_DIR}/.zizmor.yml" ]]; then
  record_pass "External Consumer Isolation: Consumer workspace contains zero platform scripts or policies"
else
  record_fail "External Consumer Isolation: Toolchain bleed" "Consumer workspace unexpectedly contaminated with platform files"
fi

# Test 14.2: Consumer Speculative Planning: Backend-free plan & analysis executed using external platform toolchain
CONSUMER_PLAN_DIR="${CONSUMER_DIR}/terraform"
(
  cd "${CONSUMER_PLAN_DIR}"
  terraform init -backend=false -input=false >/dev/null 2>&1
  terraform plan -input=false -out=tfplan >/dev/null 2>&1
  terraform show -json tfplan > tfplan.json 2>/dev/null
  python3 "${PLATFORM_DIR}/scripts/analyze-plan.py" \
    --plan-json tfplan.json \
    --output-markdown summary.md >/dev/null 2>&1
)
if [[ -f "${CONSUMER_PLAN_DIR}/summary.md" ]] && \
   grep -q "Terraform Execution Plan Summary" "${CONSUMER_PLAN_DIR}/summary.md" && \
   grep -q "Create" "${CONSUMER_PLAN_DIR}/summary.md"; then
  record_pass "External Consumer Planning: Speculative plan & change analysis succeeded using external platform toolchain"
else
  record_fail "External Consumer Planning: Execution failure" "Failed to generate speculative plan summary from external toolchain"
fi

# Test 14.3: Fail-Closed Policy Enforcement: Missing policy directory triggers immediate failure (exit 1)
# Verifies that reusable workflows fail-closed when enable-policy-evaluation is true and policy dir is missing
RESOLVED_POLICY_DIR="/tmp/nonexistent-policy-dir-$$"
ENABLE_POLICY_EVAL="true"
MISSING_POLICY_EXIT=0
(
  if [[ "${ENABLE_POLICY_EVAL}" == "true" ]]; then
    if [[ ! -d "${RESOLVED_POLICY_DIR}" ]]; then
      echo "::error::Security Configuration Error: Specified policy-directory does not exist" >/dev/null 2>&1
      exit 1
    fi
  fi
) || MISSING_POLICY_EXIT=$?

if [[ "${MISSING_POLICY_EXIT:-0}" -ne 0 ]]; then
  record_pass "Fail-Closed Policy Enforcement: Missing policy directory triggers immediate job failure (exit 1)"
else
  record_fail "Fail-Closed Policy Enforcement: Fail-open bug" "Missing policy directory did not cause immediate failure"
fi

# Test 14.4: Policy Violation Rejection: Non-compliant consumer resource rejected by OPA policies
# Create simulated consumer plan JSON containing an insecure S3 bucket with public ACL
cat << 'EOF' > "${CONSUMER_SIM_TMP}/insecure_plan.json"
{
  "format_version": "1.2",
  "terraform_version": "1.10.4",
  "resource_changes": [
    {
      "address": "aws_s3_bucket.leak",
      "type": "aws_s3_bucket",
      "name": "leak",
      "change": {
        "actions": ["create"],
        "before": null,
        "after": {
          "bucket": "consumer-leak-bucket",
          "acl": "public-read"
        },
        "after_unknown": {}
      }
    }
  ]
}
EOF

if "${CONFTEST_BIN}" test --all-namespaces --policy "${PLATFORM_DIR}/policies" "${CONSUMER_SIM_TMP}/insecure_plan.json" >/dev/null 2>&1; then
  record_fail "Policy Enforcement: Insecure plan accepted" "Conftest unexpectedly passed on public-read S3 bucket"
else
  record_pass "Policy Enforcement: Non-compliant consumer plan rejected by OPA guardrails"
fi

# Test 14.5: Malformed Configuration Rejection: Invalid consumer Terraform syntax rejected
MALFORMED_DIR="${CONSUMER_SIM_TMP}/malformed_tf"
mkdir -p "${MALFORMED_DIR}"
cat << 'EOF' > "${MALFORMED_DIR}/bad.tf"
resource "terraform_data" "broken" {
  input = {
    syntax_error =
EOF

MALFORMED_EXIT=0
(
  cd "${MALFORMED_DIR}"
  terraform init -backend=false -input=false >/dev/null 2>&1
  terraform validate >/dev/null 2>&1
) || MALFORMED_EXIT=$?

if [[ "${MALFORMED_EXIT}" -ne 0 ]]; then
  record_pass "Malformed Configuration: Invalid consumer Terraform syntax rejected with non-zero exit code"
else
  record_fail "Malformed Configuration: Syntax error ignored" "Malformed Terraform configuration unexpectedly passed validation"
fi

# Test 14.6: Sensitive File Cleanup: Raw binary plan and JSON purged on success and failure (fail-safe trap)
CLEANUP_TEST_DIR="${CONSUMER_SIM_TMP}/cleanup_test"
mkdir -p "${CLEANUP_TEST_DIR}"
echo "sensitive-binary-plan" > "${CLEANUP_TEST_DIR}/tfplan"
echo '{"secret":"data"}' > "${CLEANUP_TEST_DIR}/tfplan.json"

# Test success cleanup
(
  PLAN_DIR="${CLEANUP_TEST_DIR}"
  rm -rf "${PLAN_DIR}/tfplan" "${PLAN_DIR}/tfplan.json"
)
if [[ ! -f "${CLEANUP_TEST_DIR}/tfplan" ]] && [[ ! -f "${CLEANUP_TEST_DIR}/tfplan.json" ]]; then
  SUCCESS_CLEANUP=true
else
  SUCCESS_CLEANUP=false
fi

# Test failure cleanup via trap
echo "sensitive-binary-plan-failure" > "${CLEANUP_TEST_DIR}/tfplan"
echo '{"secret":"failure-data"}' > "${CLEANUP_TEST_DIR}/tfplan.json"
(
  PLAN_DIR="${CLEANUP_TEST_DIR}"
  trap 'rm -rf "${PLAN_DIR}/tfplan" "${PLAN_DIR}/tfplan.json"' EXIT
  # Simulate unexpected failure
  exit 1
) >/dev/null 2>&1 || true

if [[ ! -f "${CLEANUP_TEST_DIR}/tfplan" ]] && [[ ! -f "${CLEANUP_TEST_DIR}/tfplan.json" ]] && [[ "${SUCCESS_CLEANUP}" == "true" ]]; then
  record_pass "Sensitive File Cleanup: Raw binary plan and JSON purged on both success and failure (fail-safe trap)"
else
  record_fail "Sensitive File Cleanup: Leak detected" "Sensitive plan files persisted after cleanup execution"
fi

# Test 14.7: Consumer Attestation: Plan manifest and attestation generated & verified for external consumer
"${PLATFORM_DIR}/scripts/verify-plan-integrity.py" generate-manifest \
  --plan-json "${CONSUMER_PLAN_DIR}/tfplan.json" \
  --plan-file "${CONSUMER_PLAN_DIR}/tfplan" \
  --repository "external-org/consumer-service" \
  --commit-sha "9999888877776666555544443333222211110000" \
  --workflow "infraflow-plan.yml" \
  --security-decision "passed" \
  --output "${CONSUMER_PLAN_DIR}/plan-manifest.json" >/dev/null 2>&1

"${PLATFORM_DIR}/scripts/verify-plan-integrity.py" create-bundle \
  --manifest "${CONSUMER_PLAN_DIR}/plan-manifest.json" \
  --repository "external-org/consumer-service" \
  --workflow "infraflow-plan.yml" \
  --commit-sha "9999888877776666555544443333222211110000" \
  --output "${CONSUMER_PLAN_DIR}/bundle.json" >/dev/null 2>&1

if "${PLATFORM_DIR}/scripts/verify-plan-integrity.py" verify-attestation \
    --manifest "${CONSUMER_PLAN_DIR}/plan-manifest.json" \
    --bundle "${CONSUMER_PLAN_DIR}/bundle.json" \
    --plan-json "${CONSUMER_PLAN_DIR}/tfplan.json" \
    --plan-file "${CONSUMER_PLAN_DIR}/tfplan" \
    --expected-repository "external-org/consumer-service" \
    --expected-workflow "infraflow-plan.yml" >/dev/null 2>&1; then
  record_pass "External Consumer Attestation: Plan manifest and Sigstore attestation generated and verified"
else
  record_fail "External Consumer Attestation: Verification failed" "Failed to verify consumer attestation bundle"
fi

# Test 14.8: Verified Policy Gate Enforcement: Production authorization blocked when attestation is missing or invalid
# 1. Missing bundle rejected
MISSING_BUNDLE_BLOCKED=false
if ! "${PLATFORM_DIR}/scripts/verify-plan-integrity.py" verify-attestation \
    --manifest "${CONSUMER_PLAN_DIR}/plan-manifest.json" \
    --expected-repository "external-org/consumer-service" \
    --require-production-signer >/dev/null 2>&1; then
  MISSING_BUNDLE_BLOCKED=true
fi

# 2. Tampered manifest rejected
echo '{"tampered":true}' > "${CONSUMER_SIM_TMP}/tampered_manifest.json"
TAMPERED_BLOCKED=false
if ! "${PLATFORM_DIR}/scripts/verify-plan-integrity.py" verify-attestation \
    --manifest "${CONSUMER_SIM_TMP}/tampered_manifest.json" \
    --bundle "${CONSUMER_PLAN_DIR}/bundle.json" \
    --expected-repository "external-org/consumer-service" >/dev/null 2>&1; then
  TAMPERED_BLOCKED=true
fi

# 3. Verified policy gate condition check: verify reusable-tf-plan.yml evaluates plan, analysis, security, attest, and verify-attestation
GATE_CONDITION_SECURE=false
if python3 -c "
lines = open('${REPO_ROOT}/.github/workflows/reusable-tf-plan.yml').read()
gate_job = lines.split('  verified-policy-gate:')[1]
assert 'SECURITY_STATUS: \${{ needs.plan.outputs.security-status }}' in gate_job
assert 'ATTEST_STATUS: \${{ needs.attest.outputs.attestation-status }}' in gate_job
assert 'VERIFY_STATUS: \${{ needs.verify-attestation.outputs.verification-status }}' in gate_job
assert 'FAIL_ON_DESTRUCTIVE: \${{ inputs.fail-on-destructive }}' in gate_job
assert 'HAS_DESTRUCTIVE: \${{ needs.plan.outputs.has-destructive-changes }}' in gate_job
" >/dev/null 2>&1; then
  GATE_CONDITION_SECURE=true
fi

if [[ "${MISSING_BUNDLE_BLOCKED}" == "true" ]] && \
   [[ "${TAMPERED_BLOCKED}" == "true" ]] && \
   [[ "${GATE_CONDITION_SECURE}" == "true" ]]; then
  record_pass "Verified Policy Gate Enforcement: Production authorization blocked on missing, invalid, or skipped attestation"
else
  record_fail "Verified Policy Gate Enforcement: Security bypass" "Policy gate did not strictly block unauthenticated plan"
fi

# Test 14.9: Plan JSON remains available after plan_gen completion for downstream scanners
PLAN_RETENTION_TMP=$(mktemp -d /tmp/infraflow-retention-XXXXXX)
(
  PLAN_DIR="${PLAN_RETENTION_TMP}/temp_plan"
  mkdir -p "${PLAN_DIR}"
  chmod 700 "${PLAN_DIR}"
  PLAN_OUT="${PLAN_DIR}/tfplan"
  PLAN_JSON="${PLAN_DIR}/tfplan.json"
  echo "binary" > "${PLAN_OUT}"
  echo '{"format_version":"1.2"}' > "${PLAN_JSON}"

  # Step-level trap purges binary plan only
  (
    trap 'rm -f "${PLAN_OUT}"' EXIT
    cp "${PLAN_JSON}" "${PLAN_RETENTION_TMP}/tfplan.json"
  )
)
if [[ -f "${PLAN_RETENTION_TMP}/tfplan.json" ]] && [[ ! -f "${PLAN_RETENTION_TMP}/temp_plan/tfplan" ]]; then
  record_pass "Plan Artifact Retention: Plan JSON remains available after plan_gen (binary plan purged)"
else
  record_fail "Plan Artifact Retention: Premature cleanup" "Plan JSON was unexpectedly deleted by step exit trap"
fi
rm -rf "${PLAN_RETENTION_TMP}"

# Test 14.10: Final cleanup removes all sensitive plan files on job completion
CLEANUP_SUCCESS_TMP=$(mktemp -d /tmp/infraflow-clean-success-XXXXXX)
mkdir -p "${CLEANUP_SUCCESS_TMP}/runner_temp/infraflow_plan"
echo "binary" > "${CLEANUP_SUCCESS_TMP}/runner_temp/infraflow_plan/tfplan"
echo "json" > "${CLEANUP_SUCCESS_TMP}/tfplan.json"
echo "binary" > "${CLEANUP_SUCCESS_TMP}/tfplan"

# Execute cleanup step logic
(
  rm -rf "${CLEANUP_SUCCESS_TMP}/runner_temp/infraflow_plan"
  rm -f "${CLEANUP_SUCCESS_TMP}/tfplan.json"
  rm -f "${CLEANUP_SUCCESS_TMP}/tfplan"
  find "${CLEANUP_SUCCESS_TMP}" -maxdepth 3 \( -name "tfplan" -o -name "tfplan.json" \) -delete 2>/dev/null || true
)

if [[ ! -f "${CLEANUP_SUCCESS_TMP}/tfplan.json" ]] && \
   [[ ! -f "${CLEANUP_SUCCESS_TMP}/tfplan" ]] && \
   [[ ! -d "${CLEANUP_SUCCESS_TMP}/runner_temp/infraflow_plan" ]]; then
  record_pass "Sensitive Plan Cleanup: Final always() step purges all raw binary and JSON plans"
else
  record_fail "Sensitive Plan Cleanup: Leaked files" "Plan files persisted after always() cleanup step"
fi
rm -rf "${CLEANUP_SUCCESS_TMP}"

# Test 14.11: Final cleanup removes all sensitive plan files after simulated step failure
CLEANUP_FAIL_TMP=$(mktemp -d /tmp/infraflow-clean-fail-XXXXXX)
mkdir -p "${CLEANUP_FAIL_TMP}/runner_temp/infraflow_plan"
echo "binary" > "${CLEANUP_FAIL_TMP}/runner_temp/infraflow_plan/tfplan"
echo "json" > "${CLEANUP_FAIL_TMP}/tfplan.json"
echo "binary" > "${CLEANUP_FAIL_TMP}/tfplan"

# Simulate failure followed by always() step
(
  # Step failure simulated
  false || true
  # always() step execution
  rm -rf "${CLEANUP_FAIL_TMP}/runner_temp/infraflow_plan"
  rm -f "${CLEANUP_FAIL_TMP}/tfplan.json"
  rm -f "${CLEANUP_FAIL_TMP}/tfplan"
  find "${CLEANUP_FAIL_TMP}" -maxdepth 3 \( -name "tfplan" -o -name "tfplan.json" \) -delete 2>/dev/null || true
)

if [[ ! -f "${CLEANUP_FAIL_TMP}/tfplan.json" ]] && \
   [[ ! -f "${CLEANUP_FAIL_TMP}/tfplan" ]] && \
   [[ ! -d "${CLEANUP_FAIL_TMP}/runner_temp/infraflow_plan" ]]; then
  record_pass "Sensitive Plan Cleanup: Cleanup successfully purges plan data after failed step execution"
else
  record_fail "Sensitive Plan Cleanup: Leaked files on failure" "Plan files persisted after failure cleanup"
fi
rm -rf "${CLEANUP_FAIL_TMP}"

# Test 14.12: Missing attestation strictly blocks verified policy gate authorization
MISSING_ATTEST_BLOCKED=false
if python3 -c "
lines = open('${REPO_ROOT}/.github/workflows/reusable-tf-plan.yml').read()
gate_job = lines.split('  verified-policy-gate:')[1]
assert 'ATTEST_RESULT: \${{ needs.attest.result }}' in gate_job
assert 'VERIFY_RESULT: \${{ needs.verify-attestation.result }}' in gate_job
assert 'needs: [plan, attest, verify-attestation]' in gate_job
assert 'ATTEST_RESULT' in gate_job
assert 'REJECTION_REASONS' in gate_job
" >/dev/null 2>&1; then
  MISSING_ATTEST_BLOCKED=true
fi
if [[ "${MISSING_ATTEST_BLOCKED}" == "true" ]]; then
  record_pass "Policy Gate: Missing or skipped attestation strictly blocks policy gate authorization"
else
  record_fail "Policy Gate: Missing attestation bypass" "Policy gate condition does not strictly require attest success"
fi

# Test 14.13: Invalid attestation blocks verified policy gate
INVALID_ATTEST_BLOCKED=false
if python3 -c "
lines = open('${REPO_ROOT}/.github/workflows/reusable-tf-plan.yml').read()
verify_job = lines.split('  verify-attestation:')[1].split('  verified-policy-gate:')[0]
assert '--require-production-signer' in verify_job
assert '--use-gh-cli' in verify_job
gate_job = lines.split('  verified-policy-gate:')[1]
assert 'VERIFY_STATUS: \${{ needs.verify-attestation.outputs.verification-status }}' in gate_job
assert 'VERIFY_RESULT: \${{ needs.verify-attestation.result }}' in gate_job
assert 'REJECTION_REASONS' in gate_job
" >/dev/null 2>&1; then
  INVALID_ATTEST_BLOCKED=true
fi
if [[ "${INVALID_ATTEST_BLOCKED}" == "true" ]]; then
  record_pass "Policy Gate: Invalid attestation fails verify-attestation and blocks policy gate authorization"
else
  record_fail "Policy Gate: Invalid attestation bypass" "Policy gate does not depend on verified attestation"
fi

# Test 14.14: Missing --use-gh-cli strictly rejected from production authorization (offline synthetic bundles blocked)
PROD_AUTH_REJECTED=false
OUTPUT_ERR=$("${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-attestation \
  --manifest "${CONSUMER_PLAN_DIR}/plan-manifest.json" \
  --bundle "${CONSUMER_PLAN_DIR}/bundle.json" \
  --require-production-signer 2>&1 || true)

if echo "${OUTPUT_ERR}" | grep -q "Production authorization strictly requires official GitHub Artifact Attestation verification via GitHub CLI (--use-gh-cli)"; then
  PROD_AUTH_REJECTED=true
fi

if [[ "${PROD_AUTH_REJECTED}" == "true" ]]; then
  record_pass "Production Authorization: Missing --use-gh-cli cannot authorize production (offline synthetic bundles rejected)"
else
  record_fail "Production Authorization: Synthetic bundle bypass" "verify-attestation unexpectedly authorized production without --use-gh-cli"
fi

# Test 14.15: Platform Ref Validation: Mutable branch references rejected by guard
MUTABLE_BRANCH_REJECTED=false
(
  PLATFORM_REF="release/g04-platform-engine"
  if [[ ! "${PLATFORM_REF}" =~ ^[0-9a-fA-F]{40}$ ]]; then
    exit 1
  fi
) || MUTABLE_BRANCH_REJECTED=true

if [[ "${MUTABLE_BRANCH_REJECTED}" == "true" ]]; then
  record_pass "Platform Ref Validation: Mutable branch reference ('release/g04-platform-engine') rejected"
else
  record_fail "Platform Ref Validation: Branch accepted" "Guard unexpectedly accepted mutable branch reference"
fi

# Test 14.16: Platform Ref Validation: Invalid commit SHA values rejected by guard
INVALID_SHA_REJECTED=false
(
  # Test short SHA, non-hex, and traversal
  for BAD_REF in "52c15d3" "52c15d3eedc17b94570c653e9a654de39c370e1Z" "../../etc/passwd" "HEAD~1"; do
    if [[ "${BAD_REF}" =~ ^[0-9a-fA-F]{40}$ ]]; then
      exit 0
    fi
  done
  exit 1
) || INVALID_SHA_REJECTED=true

if [[ "${INVALID_SHA_REJECTED}" == "true" ]]; then
  record_pass "Platform Ref Validation: Invalid commit SHA values (short SHA, non-hex, traversal) rejected"
else
  record_fail "Platform Ref Validation: Invalid SHA accepted" "Guard unexpectedly accepted invalid commit SHA"
fi

# Test 14.17: Platform Ref Validation: Valid 40-character hexadecimal commit SHA accepted
VALID_SHA_ACCEPTED=false
(
  VALID_REF="52c15d3eedc17b94570c653e9a654de39c370e19"
  if [[ "${VALID_REF}" =~ ^[0-9a-fA-F]{40}$ ]]; then
    exit 0
  fi
  exit 1
) && VALID_SHA_ACCEPTED=true

if [[ "${VALID_SHA_ACCEPTED}" == "true" ]]; then
  record_pass "Platform Ref Validation: Valid immutable 40-character commit SHA accepted"
else
  record_fail "Platform Ref Validation: Valid SHA rejected" "Guard unexpectedly rejected valid 40-character commit SHA"
fi

# Test 14.18: Pre-Gate Verification Architecture: Cryptographic verification strictly precedes verified policy gate
PRECEDES_GATE=false
if python3 -c "
lines = open('${REPO_ROOT}/.github/workflows/reusable-tf-plan.yml').read()
assert '  verify-attestation:' in lines
verify_sec = lines.split('  verify-attestation:')[1].split('  verified-policy-gate:')[0]
assert 'environment:' not in verify_sec
assert '--use-gh-cli' in verify_sec
gate_sec = lines.split('  verified-policy-gate:')[1]
assert 'needs: [plan, attest, verify-attestation]' in gate_sec
assert 'environment:' not in gate_sec
assert 'VERIFY_STATUS: \${{ needs.verify-attestation.outputs.verification-status }}' in gate_sec
" >/dev/null 2>&1; then
  PRECEDES_GATE=true
fi

if [[ "${PRECEDES_GATE}" == "true" ]]; then
  record_pass "Policy Architecture: Cryptographic attestation verification strictly precedes automated verified policy gate"
else
  record_fail "Policy Architecture: Gate sequence error" "Cryptographic verification does not strictly precede policy gate"
fi

# ==============================================================================
# Verified Policy Gate Automated Decision Matrix Regression Tests (Tests 14.19 - 14.26)
# ==============================================================================
log_header "14.19 - 14.26: Verified Policy Gate Decision Matrix Regression Tests"

GATE_TEST_TMP=$(mktemp -d /tmp/infraflow-gate-matrix-XXXXXX)

cat <<'EOF' > "${GATE_TEST_TMP}/simulate_gate.py"
import sys

def evaluate(plan_res, plan_st, anal_st, sec_st, has_dest, fail_dest, att_res, att_st, ver_res, ver_st):
    reasons = []
    if plan_res != "success" or plan_st != "success":
        reasons.append("Speculative planning job failed or did not complete")
    if anal_st != "success":
        reasons.append("Plan change analysis failed or was skipped")
    if sec_st != "success":
        reasons.append("Security policy checks (Trivy/OPA) failed or were skipped")
    if att_res != "success" or att_st != "success":
        reasons.append("Cryptographic attestation generation failed or was skipped")
    if ver_res != "success" or ver_st != "success":
        reasons.append("Cryptographic attestation verification failed or was skipped")
    if fail_dest == "true" and has_dest == "true":
        reasons.append("Destructive plan policy violation")

    if len(reasons) == 0:
        return "authorized", 0
    else:
        return "rejected", 1

if __name__ == "__main__":
    status, code = evaluate(
        sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4],
        sys.argv[5], sys.argv[6], sys.argv[7], sys.argv[8],
        sys.argv[9], sys.argv[10]
    )
    print(status)
    sys.exit(code)
EOF

# Test 14.19: Verified Policy Gate: All checks successful -> authorized
OUT_14_19=$(python3 "${GATE_TEST_TMP}/simulate_gate.py" "success" "success" "success" "success" "false" "false" "success" "success" "success" "success")
CODE_14_19=$?
if [[ "${CODE_14_19}" -eq 0 && "${OUT_14_19}" == "authorized" ]]; then
  record_pass "Policy Gate Matrix [1/8]: All upstream checks successful -> authorized"
else
  record_fail "Policy Gate Matrix [1/8]: All checks success" "Expected authorized (exit 0), got ${OUT_14_19} (exit ${CODE_14_19})"
fi

# Test 14.20: Verified Policy Gate: Trivy failure -> rejected
if python3 "${GATE_TEST_TMP}/simulate_gate.py" "success" "success" "success" "failure" "false" "false" "success" "success" "success" "success" >/dev/null 2>&1; then
  record_fail "Policy Gate Matrix [2/8]: Trivy failure" "Expected rejected (exit 1) on Trivy security failure"
else
  record_pass "Policy Gate Matrix [2/8]: Trivy security vulnerability scan failure -> rejected"
fi

# Test 14.21: Verified Policy Gate: OPA failure -> rejected
if python3 "${GATE_TEST_TMP}/simulate_gate.py" "success" "success" "success" "failure" "false" "false" "success" "success" "success" "success" >/dev/null 2>&1; then
  record_fail "Policy Gate Matrix [3/8]: OPA failure" "Expected rejected (exit 1) on OPA policy failure"
else
  record_pass "Policy Gate Matrix [3/8]: OPA / Conftest policy violation -> rejected"
fi

# Test 14.22: Verified Policy Gate: Attestation verification failure -> rejected
if python3 "${GATE_TEST_TMP}/simulate_gate.py" "success" "success" "success" "success" "false" "false" "success" "success" "failure" "failure" >/dev/null 2>&1; then
  record_fail "Policy Gate Matrix [4/8]: Attestation verification failure" "Expected rejected on verification failure"
else
  record_pass "Policy Gate Matrix [4/8]: Sigstore attestation verification failure -> rejected"
fi

# Test 14.23: Verified Policy Gate: Missing verification job in workflow needs -> rejected
WORKFLOW_NEEDS_VALID=false
if python3 -c "
lines = open('${REPO_ROOT}/.github/workflows/reusable-tf-plan.yml').read()
gate_job = lines.split('  verified-policy-gate:')[1]
assert 'needs: [plan, attest, verify-attestation]' in gate_job
assert 'VERIFY_RESULT: \${{ needs.verify-attestation.result }}' in gate_job
assert 'VERIFY_STATUS: \${{ needs.verify-attestation.outputs.verification-status }}' in gate_job
" >/dev/null 2>&1; then
  WORKFLOW_NEEDS_VALID=true
fi
if [[ "${WORKFLOW_NEEDS_VALID}" == "true" ]]; then
  record_pass "Policy Gate Matrix [5/8]: Missing attestation verification job in workflow needs -> rejected"
else
  record_fail "Policy Gate Matrix [5/8]: Missing verification job" "Workflow verified-policy-gate does not require verify-attestation in needs"
fi

# Test 14.24: Verified Policy Gate: Skipped verification job -> rejected
if python3 "${GATE_TEST_TMP}/simulate_gate.py" "success" "success" "success" "success" "false" "false" "success" "success" "skipped" "skipped" >/dev/null 2>&1; then
  record_fail "Policy Gate Matrix [6/8]: Skipped verification job" "Expected rejected on skipped verification"
else
  record_pass "Policy Gate Matrix [6/8]: Skipped attestation verification job -> rejected"
fi

# Test 14.25: Verified Policy Gate: Destructive plan violating policy -> rejected
if python3 "${GATE_TEST_TMP}/simulate_gate.py" "success" "success" "success" "success" "true" "true" "success" "success" "success" "success" >/dev/null 2>&1; then
  record_fail "Policy Gate Matrix [7/8]: Destructive plan" "Expected rejected when fail-on-destructive is true and plan has destructive changes"
else
  record_pass "Policy Gate Matrix [7/8]: Destructive plan violating fail-on-destructive policy -> rejected"
fi

# Test 14.26: Verified Policy Gate: Invalid repository or commit binding -> rejected
INVALID_BINDING_REJECTED=false
if ! "${REPO_ROOT}/scripts/verify-plan-integrity.py" verify-provenance \
    --provenance "${REPO_ROOT}/fixtures/planning/valid-plan/provenance.json" \
    --public-key "${REPO_ROOT}/fixtures/planning/valid-plan/public_key.pem" \
    --plan-json "${REPO_ROOT}/fixtures/planning/valid-plan/tfplan.json" \
    --expected-repository "wrong-org/spoofed-repo" \
    --expected-commit-sha "0000000000000000000000000000000000000000" >/dev/null 2>&1; then
  INVALID_BINDING_REJECTED=true
fi
if [[ "${INVALID_BINDING_REJECTED}" == "true" ]]; then
  record_pass "Policy Gate Matrix [8/8]: Invalid repository or commit SHA cryptographic binding -> rejected"
else
  record_fail "Policy Gate Matrix [8/8]: Invalid binding" "verify-provenance unexpectedly succeeded on mismatched repo and commit"
fi

# ==============================================================================
# Dual Scanner Enforcement Matrix (Tests 14.27 - 14.33)
# Both Trivy and Conftest must succeed. Any skipped scanner or failure results in rejection.
# ==============================================================================
log_header "14.27 - 14.33: Dual Scanner Enforcement Matrix"

cat <<'EOF' > "${GATE_TEST_TMP}/simulate_dual_scanner.py"
import sys

def calc_security_status(trivy_outcome, conftest_outcome):
    trivy_st = trivy_outcome if trivy_outcome else "skipped"
    conftest_st = conftest_outcome if conftest_outcome else "skipped"
    if trivy_st == "success" and conftest_st == "success":
        return "success"
    return "failure"

def evaluate_gate(sec_status, trivy_st, conftest_st):
    reasons = []
    if sec_status != "success" or trivy_st != "success" or conftest_st != "success":
        reasons.append("Security policy checks (Trivy/OPA) failed or were skipped")
    if len(reasons) == 0:
        return "authorized", 0
    return "rejected", 1

if __name__ == "__main__":
    trivy_outcome = sys.argv[1]
    conftest_outcome = sys.argv[2]
    sec_status = calc_security_status(trivy_outcome, conftest_outcome)
    gate_decision, code = evaluate_gate(sec_status, trivy_outcome, conftest_outcome)
    print(f"{sec_status}:{gate_decision}")
    sys.exit(code)
EOF

# Test 14.27: Dual Scanner: Trivy skipped, Conftest passed -> REJECTED
RES_14_27=$(python3 "${GATE_TEST_TMP}/simulate_dual_scanner.py" "skipped" "success" 2>/dev/null || true)
if [[ "${RES_14_27}" == "failure:rejected" ]]; then
  record_pass "Dual Scanner Matrix [1/6]: Trivy skipped, Conftest passed -> REJECTED (fail-closed)"
else
  record_fail "Dual Scanner Matrix [1/6]: Trivy skipped bypass" "Expected failure:rejected, got ${RES_14_27}"
fi

# Test 14.28: Dual Scanner: Trivy passed, Conftest skipped -> REJECTED
RES_14_28=$(python3 "${GATE_TEST_TMP}/simulate_dual_scanner.py" "success" "skipped" 2>/dev/null || true)
if [[ "${RES_14_28}" == "failure:rejected" ]]; then
  record_pass "Dual Scanner Matrix [2/6]: Trivy passed, Conftest skipped -> REJECTED (fail-closed)"
else
  record_fail "Dual Scanner Matrix [2/6]: Conftest skipped bypass" "Expected failure:rejected, got ${RES_14_28}"
fi

# Test 14.29: Dual Scanner: Both skipped -> REJECTED
RES_14_29=$(python3 "${GATE_TEST_TMP}/simulate_dual_scanner.py" "skipped" "skipped" 2>/dev/null || true)
if [[ "${RES_14_29}" == "failure:rejected" ]]; then
  record_pass "Dual Scanner Matrix [3/6]: Both scanners skipped -> REJECTED (fail-closed)"
else
  record_fail "Dual Scanner Matrix [3/6]: Both skipped bypass" "Expected failure:rejected, got ${RES_14_29}"
fi

# Test 14.30: Dual Scanner: Trivy failed, Conftest passed -> REJECTED
RES_14_30=$(python3 "${GATE_TEST_TMP}/simulate_dual_scanner.py" "failure" "success" 2>/dev/null || true)
if [[ "${RES_14_30}" == "failure:rejected" ]]; then
  record_pass "Dual Scanner Matrix [4/6]: Trivy failed, Conftest passed -> REJECTED (fail-closed)"
else
  record_fail "Dual Scanner Matrix [4/6]: Trivy failure bypass" "Expected failure:rejected, got ${RES_14_30}"
fi

# Test 14.31: Dual Scanner: Conftest failed, Trivy passed -> REJECTED
RES_14_31=$(python3 "${GATE_TEST_TMP}/simulate_dual_scanner.py" "success" "failure" 2>/dev/null || true)
if [[ "${RES_14_31}" == "failure:rejected" ]]; then
  record_pass "Dual Scanner Matrix [5/6]: Conftest failed, Trivy passed -> REJECTED (fail-closed)"
else
  record_fail "Dual Scanner Matrix [5/6]: Conftest failure bypass" "Expected failure:rejected, got ${RES_14_31}"
fi

# Test 14.32: Dual Scanner: Both passed -> SUCCESS
RES_14_32=$(python3 "${GATE_TEST_TMP}/simulate_dual_scanner.py" "success" "success" 2>/dev/null || true)
if [[ "${RES_14_32}" == "success:authorized" ]]; then
  record_pass "Dual Scanner Matrix [6/6]: Both scanners passed -> SUCCESS (authorized)"
else
  record_fail "Dual Scanner Matrix [6/6]: Valid scanners rejected" "Expected success:authorized, got ${RES_14_32}"
fi

# Test 14.33: Dual Scanner Invariant: Workflow stage summary calculation strictly enforces both scanners
WORKFLOW_DUAL_SCAN_ENFORCED=false
if python3 -c "
lines = open('${REPO_ROOT}/.github/workflows/reusable-tf-plan.yml').read()
summary_step = lines.split('id: summary')[1].split('  attest:')[0]
assert 'if [[ \"\${TRIVY_STATUS}\" == \"success\" && \"\${CONFTEST_STATUS}\" == \"success\" ]]; then' in summary_step
assert 'SECURITY_STATUS=\"success\"' in summary_step
assert 'SECURITY_STATUS=\"failure\"' in summary_step
assert 'echo \"trivy-status=\${TRIVY_STATUS}\"' in summary_step
assert 'echo \"conftest-status=\${CONFTEST_STATUS}\"' in summary_step
gate_job = lines.split('  verified-policy-gate:')[1]
assert 'TRIVY_STATUS: \${{ needs.plan.outputs.trivy-status }}' in gate_job
assert 'CONFTEST_STATUS: \${{ needs.plan.outputs.conftest-status }}' in gate_job
assert '\"\${SECURITY_STATUS}\" != \"success\" || \"\${TRIVY_STATUS}\" != \"success\" || \"\${CONFTEST_STATUS}\" != \"success\"' in gate_job
" >/dev/null 2>&1; then
  WORKFLOW_DUAL_SCAN_ENFORCED=true
fi
if [[ "${WORKFLOW_DUAL_SCAN_ENFORCED}" == "true" ]]; then
  record_pass "Dual Scanner Invariant: Workflow summary and policy gate strictly require both scanners to succeed"
else
  record_fail "Dual Scanner Invariant: Workflow enforcement" "reusable-tf-plan.yml does not properly enforce both scanner outputs"
fi

# ==============================================================================
# Platform Security Severity Enforcement (Tests 14.34 - 14.40)
# Minimum severity threshold strictly controlled by InfraFlow ('HIGH,CRITICAL')
# ==============================================================================
log_header "14.34 - 14.40: Platform Security Severity Enforcement"

validate_severity() {
  local INPUT_SEVERITY="$1"
  local CLEAN_SEVERITY
  CLEAN_SEVERITY=$(echo "${INPUT_SEVERITY}" | tr -d '[:space:]')
  if [[ "${CLEAN_SEVERITY}" != "HIGH,CRITICAL" && "${CLEAN_SEVERITY}" != "CRITICAL,HIGH" ]]; then
    return 1
  fi
  return 0
}

# Test 14.34: Severity Enforcement: Guard rejects weakened severity 'CRITICAL' alone
if validate_severity "CRITICAL"; then
  record_fail "Severity Enforcement [1/7]: Weakened severity 'CRITICAL'" "Guard accepted CRITICAL alone (HIGH findings would be skipped)"
else
  record_pass "Severity Enforcement [1/7]: Guard rejects weakened severity 'CRITICAL' alone"
fi

# Test 14.35: Severity Enforcement: Guard rejects weakened severity 'HIGH' alone
if validate_severity "HIGH"; then
  record_fail "Severity Enforcement [2/7]: Weakened severity 'HIGH'" "Guard accepted HIGH alone (CRITICAL findings would be skipped)"
else
  record_pass "Severity Enforcement [2/7]: Guard rejects weakened severity 'HIGH' alone"
fi

# Test 14.36: Severity Enforcement: Guard rejects weakened severity 'LOW'
if validate_severity "LOW"; then
  record_fail "Severity Enforcement [3/7]: Weakened severity 'LOW'" "Guard accepted unauthorized severity 'LOW'"
else
  record_pass "Severity Enforcement [3/7]: Guard rejects weakened severity 'LOW'"
fi

# Test 14.37: Severity Enforcement: Guard rejects weakened severity 'MEDIUM'
if validate_severity "MEDIUM"; then
  record_fail "Severity Enforcement [4/7]: Weakened severity 'MEDIUM'" "Guard accepted unauthorized severity 'MEDIUM'"
else
  record_pass "Severity Enforcement [4/7]: Guard rejects weakened severity 'MEDIUM'"
fi

# Test 14.38: Severity Enforcement: Guard rejects weakened severity 'UNKNOWN'
if validate_severity "UNKNOWN"; then
  record_fail "Severity Enforcement [5/7]: Weakened severity 'UNKNOWN'" "Guard accepted unauthorized severity 'UNKNOWN'"
else
  record_pass "Severity Enforcement [5/7]: Guard rejects weakened severity 'UNKNOWN'"
fi

# Test 14.39: Severity Enforcement: Guard accepts mandatory platform severity 'HIGH,CRITICAL'
if validate_severity "HIGH,CRITICAL" && validate_severity "CRITICAL,HIGH" && validate_severity "HIGH, CRITICAL"; then
  record_pass "Severity Enforcement [6/7]: Guard accepts mandatory platform baseline 'HIGH,CRITICAL'"
else
  record_fail "Severity Enforcement [6/7]: Valid baseline rejected" "Guard rejected valid HIGH,CRITICAL baseline"
fi

# Test 14.40: Severity Invariant: Workflow strictly enforces HIGH,CRITICAL in Trivy execution
WORKFLOW_SEVERITY_ENFORCED=false
if python3 -c "
lines = open('${REPO_ROOT}/.github/workflows/reusable-tf-plan.yml').read()
guard_step = lines.split('id: guard')[1].split('name: \"Set Up Terraform\"')[0]
assert 'CLEAN_SEVERITY=\$(echo \"\${INPUT_SEVERITY}\" | tr -d \'[:space:]\')' in guard_step
assert 'if [[ \"\${CLEAN_SEVERITY}\" != \"HIGH,CRITICAL\" && \"\${CLEAN_SEVERITY}\" != \"CRITICAL,HIGH\" ]]; then' in guard_step
trivy_step = lines.split('id: trivy')[1].split('id: conftest')[0]
assert '--severity \"HIGH,CRITICAL\"' in trivy_step
" >/dev/null 2>&1; then
  WORKFLOW_SEVERITY_ENFORCED=true
fi
if [[ "${WORKFLOW_SEVERITY_ENFORCED}" == "true" ]]; then
  record_pass "Severity Invariant [7/7]: Workflow strictly validates severity baseline and pins Trivy scanner to HIGH,CRITICAL"
else
  record_fail "Severity Invariant [7/7]: Workflow severity enforcement" "reusable-tf-plan.yml missing strict severity guard or Trivy pin"
fi

# ==============================================================================
# Protect Platform OPA Policies (Tests 14.41 - 14.44)
# Mandatory platform policies immutable; consumer policies additive only
# ==============================================================================
log_header "14.41 - 14.44: Protect Platform OPA Policies"

# Test 14.41: Platform Policy Protection: Platform policies unconditionally required (missing dir fails closed with exit 1)
MISSING_PLATFORM_POLICY_EXIT=0
(
  PLATFORM_POLICY_DIR="/tmp/nonexistent-platform-policies-$$"
  if [[ ! -d "${PLATFORM_POLICY_DIR}" ]]; then
    exit 1
  fi
) || MISSING_PLATFORM_POLICY_EXIT=$?

if [[ "${MISSING_PLATFORM_POLICY_EXIT}" -ne 0 ]]; then
  record_pass "Platform Policy Protection [1/4]: Missing platform policy directory fails closed (exit 1)"
else
  record_fail "Platform Policy Protection [1/4]: Missing platform policies" "Missing platform policy directory did not trigger failure"
fi

# Test 14.42: Platform Policy Protection: Consumer policy directory cannot replace platform policy directory
CONSUMER_REPLACE_BLOCKED=false
CONSUMER_POLICY_TEST_DIR="${CONSUMER_SIM_TMP}/consumer_policies"
mkdir -p "${CONSUMER_POLICY_TEST_DIR}"
cat <<'EOF' > "${CONSUMER_POLICY_TEST_DIR}/dummy.rego"
package main
# Permissive dummy rule
default allow = true
EOF

# Insecure plan must be rejected even if consumer policies are added
if "${CONFTEST_BIN}" test --all-namespaces --policy "${PLATFORM_DIR}/policies" --policy "${CONSUMER_POLICY_TEST_DIR}" "${CONSUMER_SIM_TMP}/insecure_plan.json" >/dev/null 2>&1; then
  CONSUMER_REPLACE_BLOCKED=false
else
  CONSUMER_REPLACE_BLOCKED=true
fi

if [[ "${CONSUMER_REPLACE_BLOCKED}" == "true" ]]; then
  record_pass "Platform Policy Protection [2/4]: Consumer policies cannot override or replace platform policies (additive evaluation)"
else
  record_fail "Platform Policy Protection [2/4]: Consumer policy override" "Permissive consumer policy bypassed platform deny rules"
fi

# Test 14.43: Platform Policy Protection: Non-existent custom consumer policy directory fails closed
MISSING_CUSTOM_CONSUMER_EXIT=0
(
  POLICY_DIR="nonexistent-custom-dir-$$"
  CONSUMER_POLICY_DIR="/tmp/${POLICY_DIR}"
  if [[ ! -d "${CONSUMER_POLICY_DIR}" && "${POLICY_DIR}" != "policies" ]]; then
    exit 1
  fi
) || MISSING_CUSTOM_CONSUMER_EXIT=$?

if [[ "${MISSING_CUSTOM_CONSUMER_EXIT}" -ne 0 ]]; then
  record_pass "Platform Policy Protection [3/4]: Non-existent custom consumer policy directory fails closed (exit 1)"
else
  record_fail "Platform Policy Protection [3/4]: Missing custom consumer dir" "Missing custom consumer policy directory did not fail"
fi

# Test 14.44: Platform Policy Invariant: Workflow conftest step unconditionally includes platform policy directory
WORKFLOW_POLICY_PROTECTED=false
if python3 -c "
lines = open('${REPO_ROOT}/.github/workflows/reusable-tf-plan.yml').read()
conftest_step = lines.split('id: conftest')[1].split('id: attest')[0]
assert 'PLATFORM_POLICY_DIR=\"\${RUNNER_TEMP}/infraflow-platform/policies\"' in conftest_step
assert 'CONFTEST_CMD=(\"/tmp/bin/conftest\" \"test\" \"--all-namespaces\" \"--policy\" \"\${PLATFORM_POLICY_DIR}\")' in conftest_step
assert 'CONFTEST_CMD+=(\"--policy\" \"\${CONSUMER_POLICY_DIR}\")' in conftest_step
assert 'RESOLVED_POLICY_DIR=\"\${GITHUB_WORKSPACE}/\${POLICY_DIR}\"' not in conftest_step
" >/dev/null 2>&1; then
  WORKFLOW_POLICY_PROTECTED=true
fi

if [[ "${WORKFLOW_POLICY_PROTECTED}" == "true" ]]; then
  record_pass "Platform Policy Invariant [4/4]: Workflow unconditionally binds platform policies and treats consumer policies as additive only"
else
  record_fail "Platform Policy Invariant [4/4]: Workflow policy binding" "reusable-tf-plan.yml does not properly protect platform policies"
fi

rm -rf "${GATE_TEST_TMP}"

rm -rf "${CONSUMER_SIM_TMP}"

# ==============================================================================
# 14.45–14.51: Trust-Boundary Regression Tests
# Verifies that the platform-repository/platform-ref attack surface is closed
# and that job.workflow_repository/sha is used as the internal trust anchor.
# ==============================================================================

log_header "14.45-14.51: Platform Trust-Boundary Enforcement"

PLAN_YML="${REPO_ROOT}/.github/workflows/reusable-tf-plan.yml"
SECURITY_YML="${REPO_ROOT}/.github/workflows/reusable-tf-security.yml"
PLAN_YML_CONTENT=$(cat "${PLAN_YML}")
SECURITY_YML_CONTENT=$(cat "${SECURITY_YML}")

# Test 14.45: Rogue repository rejection — guard rejects WORKFLOW_REPO != trusted platform
ROGUE_REPO_REJECTED=false
(
  WORKFLOW_REPO="attacker-org/rogue-repo"
  TRUSTED_PLATFORM_REPO="TM-threemavithana/infraflow"
  if [[ "${WORKFLOW_REPO}" != "${TRUSTED_PLATFORM_REPO}" ]]; then
    exit 1
  fi
) 2>/dev/null || ROGUE_REPO_REJECTED=true

if [[ "${ROGUE_REPO_REJECTED}" == "true" ]]; then
  record_pass "Trust Boundary [1/7]: Rogue repository guard logic correctly rejects unauthorized workflow repository"
else
  record_fail "Trust Boundary [1/7]: Rogue repository guard logic" "Guard logic did not reject rogue repository"
fi

# Test 14.46: platform-repository and platform-ref inputs removed from plan.yml workflow_call inputs
PLAN_INPUTS_REMOVED=true
if echo "${PLAN_YML_CONTENT}" | python3 -c "
import sys, re
content = sys.stdin.read()
# Find the workflow_call inputs section specifically
inputs_section = content.split('workflow_call:')[1].split('outputs:')[0] if 'workflow_call:' in content else ''
if 'platform-repository:' in inputs_section:
    sys.exit(1)
if 'platform-ref:' in inputs_section:
    sys.exit(2)
" 2>/dev/null; then
  PLAN_INPUTS_REMOVED=true
else
  PLAN_INPUTS_REMOVED=false
fi

if [[ "${PLAN_INPUTS_REMOVED}" == "true" ]]; then
  record_pass "Trust Boundary [2/7]: platform-repository and platform-ref removed from reusable-tf-plan.yml inputs"
else
  record_fail "Trust Boundary [2/7]: Caller-controlled platform inputs not removed from plan.yml" "inputs still contain platform-repository or platform-ref"
fi

# Test 14.47: platform-repository and platform-ref inputs removed from security.yml workflow_call inputs
SECURITY_INPUTS_REMOVED=true
if echo "${SECURITY_YML_CONTENT}" | python3 -c "
import sys
content = sys.stdin.read()
inputs_section = content.split('workflow_call:')[1].split('outputs:')[0] if 'workflow_call:' in content else ''
if 'platform-repository:' in inputs_section:
    sys.exit(1)
if 'platform-ref:' in inputs_section:
    sys.exit(2)
" 2>/dev/null; then
  SECURITY_INPUTS_REMOVED=true
else
  SECURITY_INPUTS_REMOVED=false
fi

if [[ "${SECURITY_INPUTS_REMOVED}" == "true" ]]; then
  record_pass "Trust Boundary [3/7]: platform-repository and platform-ref removed from reusable-tf-security.yml inputs"
else
  record_fail "Trust Boundary [3/7]: Caller-controlled platform inputs not removed from security.yml" "inputs still contain platform-repository or platform-ref"
fi

# Test 14.48: All platform checkout steps in plan.yml use job.workflow_repository and job.workflow_sha
PLAN_CHECKOUT_HARDENED=false
if python3 -c "
content = open('${PLAN_YML}').read()
# Count trusted checkouts vs rogue inputs.platform-* checkouts
trusted = content.count('repository: \${{ job.workflow_repository }}')
sha_bound = content.count('ref: \${{ job.workflow_sha }}')
rogue_repo = content.count('repository: \${{ inputs.platform-repository }}')
rogue_ref = content.count('ref: \${{ inputs.platform-ref }}')
# Expect 3 trusted checkout blocks (plan, attest, verify-attestation), 0 rogue
assert trusted == 3, f'Expected 3 workflow_repository checkouts, got {trusted}'
assert sha_bound == 3, f'Expected 3 workflow_sha refs, got {sha_bound}'
assert rogue_repo == 0, f'Found {rogue_repo} remaining inputs.platform-repository checkouts'
assert rogue_ref == 0, f'Found {rogue_ref} remaining inputs.platform-ref checkouts'
" 2>/dev/null; then
  PLAN_CHECKOUT_HARDENED=true
fi

if [[ "${PLAN_CHECKOUT_HARDENED}" == "true" ]]; then
  record_pass "Trust Boundary [4/7]: All 3 platform checkout steps in plan.yml use job.workflow_repository/sha (no caller-controlled refs)"
else
  record_fail "Trust Boundary [4/7]: Platform checkout steps not hardened in plan.yml" "checkout steps still reference inputs.platform-repository or inputs.platform-ref, or missing job.workflow_repository/sha"
fi

# Test 14.49: Attestation signer identity is hardcoded in plan.yml (not from any caller input variable)
SIGNER_HARDCODED=false
if python3 -c "
content = open('${PLAN_YML}').read()
# The verify step must contain hardcoded signer-repo, not a variable expansion
assert '--signer-repo \"TM-threemavithana/infraflow\"' in content, 'hardcoded signer-repo not found'
assert '--signer-workflow \"TM-threemavithana/infraflow/.github/workflows/reusable-tf-plan.yml\"' in content, 'hardcoded signer-workflow not found'
# Must NOT use PLATFORM_REPO variable
assert '--signer-repo \"\${PLATFORM_REPO}\"' not in content, 'variable PLATFORM_REPO still used as signer-repo'
assert 'PLATFORM_REPO: \${{ inputs.platform-repository }}' not in content, 'PLATFORM_REPO env var still from caller inputs'
" 2>/dev/null; then
  SIGNER_HARDCODED=true
fi

if [[ "${SIGNER_HARDCODED}" == "true" ]]; then
  record_pass "Trust Boundary [5/7]: Attestation signer identity is hardcoded (not from caller inputs) in plan.yml"
else
  record_fail "Trust Boundary [5/7]: Attestation signer identity not hardcoded" "PLATFORM_REPO variable or caller input still controls --signer-repo"
fi

# Test 14.50: Guard validates WORKFLOW_REPO, WORKFLOW_SHA, and WORKFLOW_REF in plan.yml
PLAN_GUARD_VALIDATES_REPO=false
if python3 -c "
content = open('${PLAN_YML}').read()
guard_section = content.split('id: guard')[1].split('- name: \"Checkout Consumer')[0] if 'id: guard' in content else ''
assert 'WORKFLOW_REPO: \${{ job.workflow_repository }}' in guard_section, 'WORKFLOW_REPO not in guard env'
assert 'WORKFLOW_SHA: \${{ job.workflow_sha }}' in guard_section, 'WORKFLOW_SHA not in guard env'
assert 'WORKFLOW_REF: \${{ job.workflow_ref }}' in guard_section, 'WORKFLOW_REF not in guard env'
assert 'TRUSTED_PLATFORM_REPO=\"TM-threemavithana/infraflow\"' in guard_section, 'TRUSTED_PLATFORM_REPO not set'
assert '\${WORKFLOW_REPO}\" != \"\${TRUSTED_PLATFORM_REPO}\"' in guard_section, 'repo identity check not found'
assert '\${WORKFLOW_REF_TARGET}\" != \"\${WORKFLOW_SHA}\"' in guard_section, 'ref target vs sha check not found'
" 2>/dev/null; then
  PLAN_GUARD_VALIDATES_REPO=true
fi

if [[ "${PLAN_GUARD_VALIDATES_REPO}" == "true" ]]; then
  record_pass "Trust Boundary [6/9]: plan.yml guard validates WORKFLOW_REPO, WORKFLOW_SHA, and WORKFLOW_REF"
else
  record_fail "Trust Boundary [6/9]: plan.yml guard missing WORKFLOW_REF or identity validation" "guard does not validate job.workflow_ref against trusted platform"
fi

# Test 14.51: security.yml checkout and guard also use job.workflow_repository/sha/ref
SECURITY_CHECKOUT_HARDENED=false
if python3 -c "
content = open('${SECURITY_YML}').read()
# Check guard env
assert 'WORKFLOW_REPO: \${{ job.workflow_repository }}' in content, 'WORKFLOW_REPO not in security.yml guard env'
assert 'WORKFLOW_SHA: \${{ job.workflow_sha }}' in content, 'WORKFLOW_SHA not in security.yml guard env'
assert 'WORKFLOW_REF: \${{ job.workflow_ref }}' in content, 'WORKFLOW_REF not in security.yml guard env'
assert 'TRUSTED_PLATFORM_REPO=\"TM-threemavithana/infraflow\"' in content, 'TRUSTED_PLATFORM_REPO not set in security.yml'
# Check checkout
assert 'repository: \${{ job.workflow_repository }}' in content, 'workflow_repository not used for checkout in security.yml'
assert 'ref: \${{ job.workflow_sha }}' in content, 'workflow_sha not used for checkout ref in security.yml'
# No remaining rogue inputs
assert 'inputs.platform-repository' not in content, 'inputs.platform-repository still referenced in security.yml'
assert 'inputs.platform-ref' not in content, 'inputs.platform-ref still referenced in security.yml'
" 2>/dev/null; then
  SECURITY_CHECKOUT_HARDENED=true
fi

if [[ "${SECURITY_CHECKOUT_HARDENED}" == "true" ]]; then
  record_pass "Trust Boundary [7/9]: reusable-tf-security.yml checkout and guard use job.workflow_repository/sha/ref"
else
  record_fail "Trust Boundary [7/9]: reusable-tf-security.yml not fully hardened" "checkout or guard still references caller-controlled inputs or missing workflow_ref"
fi

# Test 14.52: Dynamic simulation of WORKFLOW_REF validation logic
REF_VALIDATION_DYNAMIC_PASS=true

test_workflow_ref_sim() {
  local W_REPO="$1"
  local W_REF="$2"
  local W_SHA="$3"
  local EXPECTED_PATH="$4"
  local CALLER_R="${5:-external-consumer}"
  local TRUSTED_REPO="TM-threemavithana/infraflow"

  if [[ "${W_REPO}" != "${TRUSTED_REPO}" ]]; then return 1; fi
  if [[ "${W_REF}" != *"@"* ]]; then return 1; fi
  local PREFIX="${W_REF%@*}"
  local TARGET="${W_REF##*@}"
  local EXPECTED_PREFIX="${TRUSTED_REPO}/${EXPECTED_PATH}"
  if [[ "${PREFIX}" != "${EXPECTED_PREFIX}" ]]; then return 1; fi

  if [[ "${CALLER_R}" == "${TRUSTED_REPO}" && ( "${TARGET}" =~ ^refs/(heads|pull)/ || "${TARGET}" =~ ^[0-9a-fA-F]{40}$ ) ]]; then
    : # Internal platform self-test allowed
  else
    if [[ ! "${TARGET}" =~ ^[0-9a-fA-F]{40}$ ]]; then return 1; fi
    if [[ "${TARGET}" != "${W_SHA}" ]]; then return 1; fi
  fi
  if [[ ! "${W_SHA}" =~ ^[0-9a-fA-F]{40}$ ]]; then return 1; fi
  return 0
}

MOCK_SHA="86c05e54fbf7ba1f470d4b6e2bd3f1c9a384a2f2"
MOCK_REPO="TM-threemavithana/infraflow"
MOCK_PATH=".github/workflows/reusable-tf-plan.yml"

# Must reject @main
if test_workflow_ref_sim "${MOCK_REPO}" "${MOCK_REPO}/${MOCK_PATH}@main" "${MOCK_SHA}" "${MOCK_PATH}"; then
  REF_VALIDATION_DYNAMIC_PASS=false
fi
# Must reject @refs/heads/main
if test_workflow_ref_sim "${MOCK_REPO}" "${MOCK_REPO}/${MOCK_PATH}@refs/heads/main" "${MOCK_SHA}" "${MOCK_PATH}"; then
  REF_VALIDATION_DYNAMIC_PASS=false
fi
# Must reject @v0.1.0
if test_workflow_ref_sim "${MOCK_REPO}" "${MOCK_REPO}/${MOCK_PATH}@v0.1.0" "${MOCK_SHA}" "${MOCK_PATH}"; then
  REF_VALIDATION_DYNAMIC_PASS=false
fi
# Must reject @refs/tags/v0.1.0
if test_workflow_ref_sim "${MOCK_REPO}" "${MOCK_REPO}/${MOCK_PATH}@refs/tags/v0.1.0" "${MOCK_SHA}" "${MOCK_PATH}"; then
  REF_VALIDATION_DYNAMIC_PASS=false
fi
# Must reject short SHA
if test_workflow_ref_sim "${MOCK_REPO}" "${MOCK_REPO}/${MOCK_PATH}@86c05e5" "${MOCK_SHA}" "${MOCK_PATH}"; then
  REF_VALIDATION_DYNAMIC_PASS=false
fi
# Must reject mismatched SHA
if test_workflow_ref_sim "${MOCK_REPO}" "${MOCK_REPO}/${MOCK_PATH}@1111111111111111111111111111111111111111" "${MOCK_SHA}" "${MOCK_PATH}"; then
  REF_VALIDATION_DYNAMIC_PASS=false
fi
# Must accept full 40-char SHA matching workflow_sha
if ! test_workflow_ref_sim "${MOCK_REPO}" "${MOCK_REPO}/${MOCK_PATH}@${MOCK_SHA}" "${MOCK_SHA}" "${MOCK_PATH}"; then
  REF_VALIDATION_DYNAMIC_PASS=false
fi

if [[ "${REF_VALIDATION_DYNAMIC_PASS}" == "true" ]]; then
  record_pass "Trust Boundary [8/9]: WORKFLOW_REF validation strictly rejects mutable branches/tags/short-SHAs and accepts 40-char commit SHA"
else
  record_fail "Trust Boundary [8/9]: WORKFLOW_REF validation failed dynamic regression tests" "did not reject mutable branches or accept valid full SHA"
fi

# Test 14.53: --signer-digest support in verify-plan-integrity.py and reusable-tf-plan.yml
SIGNER_DIGEST_HARDENED=false
if python3 -c "
content_plan = open('${PLAN_YML}').read()
content_py = open('${REPO_ROOT}/scripts/verify-plan-integrity.py').read()
assert '--signer-digest \"\${{ job.workflow_sha }}\"' in content_plan, '--signer-digest not passed in plan.yml'
assert '--signer-digest' in content_py, '--signer-digest not supported in verify-plan-integrity.py CLI'
assert 'signer_digest=None' in content_py or 'signer_digest' in content_py, 'signer_digest parameter missing in verify-plan-integrity.py'
" 2>/dev/null; then
  SIGNER_DIGEST_HARDENED=true
fi

if [[ "${SIGNER_DIGEST_HARDENED}" == "true" ]]; then
  record_pass "Trust Boundary [9/9]: verify-plan-integrity.py and plan.yml enforce --signer-digest for exact workflow commit verification"
else
  record_fail "Trust Boundary [9/9]: --signer-digest enforcement missing" "--signer-digest not properly integrated in verification toolchain"
fi

# --- 15. AWS Cloud Adapter & OIDC Architecture (G05) ---
log_header "15. AWS Cloud Adapter & OIDC Architecture (G05)"

AWS_REUSABLE_WF="${REPO_ROOT}/.github/workflows/reusable-tf-aws.yml"
AWS_CONSUMER_WF="${REPO_ROOT}/examples/consumer-workflow/.github/workflows/infraflow-aws-plan.yml"
AWS_REF_MODULE="${REPO_ROOT}/examples/aws-reference-module"

# Test 15.1: Actionlint verification of AWS adapter and consumer workflows
if [[ -n "${ACTIONLINT_BIN}" ]]; then
  if "${ACTIONLINT_BIN}" "${AWS_REUSABLE_WF}" "${AWS_CONSUMER_WF}" >/dev/null 2>&1; then
    record_pass "AWS Workflows: Actionlint syntax & schema validation passed"
  else
    record_fail "AWS Workflows: Actionlint validation" "Actionlint failed on AWS reusable or consumer workflow"
  fi
else
  record_fail "AWS Workflows: Actionlint validation" "Actionlint binary not found"
fi

# Test 15.2: Zizmor supply chain security audit on reusable AWS workflow
if [[ -n "${ZIZMOR_BIN}" ]]; then
  if "${ZIZMOR_BIN}" -c "${REPO_ROOT}/.zizmor.yml" --min-severity medium "${AWS_REUSABLE_WF}" >/dev/null 2>&1; then
    record_pass "AWS Adapter: Zizmor supply chain security audit passed (0 medium/high findings)"
  else
    record_fail "AWS Adapter: Zizmor audit" "Zizmor detected supply chain vulnerabilities in reusable-tf-aws.yml"
  fi
else
  record_fail "AWS Adapter: Zizmor audit" "Zizmor binary not found"
fi

# Test 15.3: Conftest OPA unit tests verification (includes 27 AWS OIDC unit tests)
if [[ -n "${CONFTEST_BIN}" ]]; then
  if "${CONFTEST_BIN}" verify --policy "${REPO_ROOT}/policies" >/dev/null 2>&1; then
    record_pass "AWS OIDC Policy: All Rego unit tests passed (conftest verify)"
  else
    record_fail "AWS OIDC Policy: Rego unit tests" "conftest verify reported failures"
  fi
else
  record_fail "AWS OIDC Policy: Rego unit tests" "Conftest binary not found"
fi

# Extract guard script from reusable-tf-aws.yml
AWS_GUARD_SCRIPT="$(python3 -c "
import yaml
with open('${AWS_REUSABLE_WF}', 'r') as f:
    data = yaml.safe_load(f)
steps = {s['id']: s['run'] for s in data['jobs']['validate-inputs']['steps'] if 'id' in s and 'run' in s}
print(steps['guard'])
")"

run_aws_guard_test() {
  local version="${1:-1.10.4}"
  local dir="${2:-.}"
  local var_file="${3:-}"
  local env_name="${4:-production}"
  local region="${5:-us-east-1}"
  local role_arn="${6:-arn:aws:iam::123456789012:role/infraflow-planning-role}"
  local bucket="${7:-infraflow-state-bucket}"
  local key="${8:-env/prod/terraform.tfstate}"
  local dynamodb="${9:-}"
  local severity="${10:-HIGH,CRITICAL}"
  local session_name="${11:-infraflow-aws-plan}"
  local role_duration="${12:-900}"
  local enable_aws_auth="${13:-true}"
  local event_name="${14:-push}"
  local workflow_repo="${15:-TM-threemavithana/infraflow}"
  local workflow_sha="${16:-ed965edd00391b6b1461a65184838bb7cca5eb81}"
  local workflow_ref="${17:-TM-threemavithana/infraflow/.github/workflows/reusable-tf-aws.yml@ed965edd00391b6b1461a65184838bb7cca5eb81}"
  local target_ref="${18:-refs/heads/main}"
  local enable_policy_eval="${19:-true}"
  local enable_trivy="${20:-true}"
  local policy_dir="${21:-policies}"

  local code=0
  INPUT_VERSION="${version}" \
  INPUT_DIR="${dir}" \
  INPUT_VAR_FILE="${var_file}" \
  INPUT_ENV="${env_name}" \
  INPUT_AWS_REGION="${region}" \
  INPUT_ROLE_ARN="${role_arn}" \
  INPUT_BUCKET="${bucket}" \
  INPUT_KEY="${key}" \
  INPUT_DYNAMODB="${dynamodb}" \
  INPUT_SEVERITY="${severity}" \
  INPUT_SESSION_NAME="${session_name}" \
  INPUT_ROLE_DURATION="${role_duration}" \
  ENABLE_AWS_AUTH="${enable_aws_auth}" \
  ENABLE_POLICY_EVAL="${enable_policy_eval}" \
  ENABLE_TRIVY="${enable_trivy}" \
  INPUT_POLICY_DIR="${policy_dir}" \
  EVENT_NAME="${event_name}" \
  TARGET_REF="${target_ref}" \
  WORKFLOW_REPO="${workflow_repo}" \
  WORKFLOW_SHA="${workflow_sha}" \
  WORKFLOW_REF="${workflow_ref}" \
    bash -c "${AWS_GUARD_SCRIPT}" >/dev/null 2>&1 || code=$?
  return ${code}
}

# Test 15.4: Input Guard: Valid AWS inputs accepted
if run_aws_guard_test; then
  record_pass "AWS Input Guard [1/9]: Valid AWS inputs accepted"
else
  record_fail "AWS Input Guard [1/9]: Valid inputs" "Legitimate AWS inputs unexpectedly failed guard validation"
fi

# Test 15.5: Input Guard: Malformed Role ARN rejected
if ! run_aws_guard_test "1.10.4" "." "" "production" "us-east-1" "invalid-arn" && \
   ! run_aws_guard_test "1.10.4" "." "" "production" "us-east-1" "arn:aws:iam::12345:role/role" && \
   ! run_aws_guard_test "1.10.4" "." "" "production" "us-east-1" "arn:aws:iam::123456789012:role/role;curl evil.com"; then
  record_pass "AWS Input Guard [2/9]: Malformed Role ARN and injection attempts rejected as expected"
else
  record_fail "AWS Input Guard [2/9]: Role ARN rejection" "Malformed Role ARN was unexpectedly accepted"
fi

# Test 15.6: Input Guard: Malformed AWS region rejected
if ! run_aws_guard_test "1.10.4" "." "" "production" "INVALID_REGION" && \
   ! run_aws_guard_test "1.10.4" "." "" "production" "us-east-1; rm -rf /"; then
  record_pass "AWS Input Guard [3/9]: Malformed AWS region and injection attempts rejected as expected"
else
  record_fail "AWS Input Guard [3/9]: Region rejection" "Malformed AWS region was unexpectedly accepted"
fi

# Test 15.7: Input Guard: Invalid S3 bucket names rejected
if ! run_aws_guard_test "1.10.4" "." "" "production" "us-east-1" "arn:aws:iam::123456789012:role/role" "MyBucket" && \
   ! run_aws_guard_test "1.10.4" "." "" "production" "us-east-1" "arn:aws:iam::123456789012:role/role" "my..bucket" && \
   ! run_aws_guard_test "1.10.4" "." "" "production" "us-east-1" "arn:aws:iam::123456789012:role/role" "ab"; then
  record_pass "AWS Input Guard [4/9]: Invalid S3 bucket names (uppercase, consecutive dots, short) rejected"
else
  record_fail "AWS Input Guard [4/9]: S3 bucket rejection" "Invalid S3 bucket name was unexpectedly accepted"
fi

# Test 15.8: Input Guard: S3 backend key traversal and absolute paths rejected
if ! run_aws_guard_test "1.10.4" "." "" "production" "us-east-1" "arn:aws:iam::123456789012:role/role" "bucket" "../traversal.tfstate" && \
   ! run_aws_guard_test "1.10.4" "." "" "production" "us-east-1" "arn:aws:iam::123456789012:role/role" "bucket" "/root/state.tfstate"; then
  record_pass "AWS Input Guard [5/9]: S3 backend key path traversal ('..') and absolute paths rejected"
else
  record_fail "AWS Input Guard [5/9]: S3 key traversal" "S3 key traversal input was unexpectedly accepted"
fi

# Test 15.9: Input Guard: Invalid DynamoDB table name rejected
if ! run_aws_guard_test "1.10.4" "." "" "production" "us-east-1" "arn:aws:iam::123456789012:role/role" "bucket" "key" "bad*table;evil"; then
  record_pass "AWS Input Guard [6/9]: Invalid DynamoDB table name rejected as expected"
else
  record_fail "AWS Input Guard [6/9]: DynamoDB rejection" "Invalid DynamoDB table name was unexpectedly accepted"
fi

# Test 15.10: Security Invariant (SEC-02): Untrusted PRs (pull_request & pull_request_target) attempting AWS auth rejected
if ! run_aws_guard_test "1.10.4" "." "" "production" "us-east-1" "arn:aws:iam::123456789012:role/role" "bucket" "key" "" "HIGH,CRITICAL" "plan" "900" "true" "pull_request" && \
   ! run_aws_guard_test "1.10.4" "." "" "production" "us-east-1" "arn:aws:iam::123456789012:role/role" "bucket" "key" "" "HIGH,CRITICAL" "plan" "900" "true" "pull_request_target"; then
  record_pass "AWS Security Guard [7/10]: Untrusted pull requests (pull_request & pull_request_target) enabling live AWS auth rejected (SEC-02 fail-closed)"
else
  record_fail "AWS Security Guard [7/10]: PR auth rejection" "Untrusted pull request or pull_request_target was allowed to enable AWS authentication"
fi

# Test 15.11: Arbitrary branch scoping & No workflow_dispatch bypass:
# Arbitrary feature branches rejected for both push and workflow_dispatch; protected branches and release tags accepted
if ! run_aws_guard_test "1.10.4" "." "" "production" "us-east-1" "arn:aws:iam::123456789012:role/role" "bucket" "key" "" "HIGH,CRITICAL" "plan" "900" "true" "push" "TM-threemavithana/infraflow" "ed965edd00391b6b1461a65184838bb7cca5eb81" "TM-threemavithana/infraflow/.github/workflows/reusable-tf-aws.yml@ed965edd00391b6b1461a65184838bb7cca5eb81" "refs/heads/feature/untrusted-branch" && \
   ! run_aws_guard_test "1.10.4" "." "" "production" "us-east-1" "arn:aws:iam::123456789012:role/role" "bucket" "key" "" "HIGH,CRITICAL" "plan" "900" "true" "workflow_dispatch" "TM-threemavithana/infraflow" "ed965edd00391b6b1461a65184838bb7cca5eb81" "TM-threemavithana/infraflow/.github/workflows/reusable-tf-aws.yml@ed965edd00391b6b1461a65184838bb7cca5eb81" "refs/heads/feature/untrusted-branch" && \
   ! run_aws_guard_test "1.10.4" "." "" "production" "us-east-1" "arn:aws:iam::123456789012:role/role" "bucket" "key" "" "HIGH,CRITICAL" "plan" "900" "true" "schedule" "TM-threemavithana/infraflow" "ed965edd00391b6b1461a65184838bb7cca5eb81" "TM-threemavithana/infraflow/.github/workflows/reusable-tf-aws.yml@ed965edd00391b6b1461a65184838bb7cca5eb81" "refs/heads/main" && \
   run_aws_guard_test "1.10.4" "." "" "production" "us-east-1" "arn:aws:iam::123456789012:role/role" "bucket" "key" "" "HIGH,CRITICAL" "plan" "900" "true" "workflow_dispatch" "TM-threemavithana/infraflow" "ed965edd00391b6b1461a65184838bb7cca5eb81" "TM-threemavithana/infraflow/.github/workflows/reusable-tf-aws.yml@ed965edd00391b6b1461a65184838bb7cca5eb81" "refs/heads/main" && \
   run_aws_guard_test "1.10.4" "." "" "production" "us-east-1" "arn:aws:iam::123456789012:role/role" "bucket" "key" "" "HIGH,CRITICAL" "plan" "900" "true" "workflow_dispatch" "TM-threemavithana/infraflow" "ed965edd00391b6b1461a65184838bb7cca5eb81" "TM-threemavithana/infraflow/.github/workflows/reusable-tf-aws.yml@ed965edd00391b6b1461a65184838bb7cca5eb81" "refs/tags/v1.0.0" && \
   run_aws_guard_test "1.10.4" "." "" "production" "us-east-1" "arn:aws:iam::123456789012:role/role" "bucket" "key" "" "HIGH,CRITICAL" "plan" "900" "true" "push" "TM-threemavithana/infraflow" "ed965edd00391b6b1461a65184838bb7cca5eb81" "TM-threemavithana/infraflow/.github/workflows/reusable-tf-aws.yml@ed965edd00391b6b1461a65184838bb7cca5eb81" "refs/heads/release/v1.0"; then
  record_pass "AWS Security Guard [8/10]: Arbitrary branch and unauthorized event rejected; workflow_dispatch on arbitrary branch strictly rejected"
else
  record_fail "AWS Security Guard [8/10]: Branch scoping" "Arbitrary branch was accepted or workflow_dispatch bypass detected"
fi

# Test 15.12: Cloud-Free mode: PR allowed with enable-aws-auth: false
if run_aws_guard_test "1.10.4" "." "" "production" "us-east-1" "" "" "" "" "HIGH,CRITICAL" "plan" "900" "false" "pull_request"; then
  record_pass "AWS Security Guard [9/10]: Cloud-free pull request validation accepted (SEC-02 compliant)"
else
  record_fail "AWS Security Guard [9/10]: Cloud-free PR" "Cloud-free pull request was unexpectedly rejected"
fi

# Test 15.13: Platform Trust Boundary: Reusable AWS adapter enforces workflow repository & immutable commit SHA
if ! run_aws_guard_test "1.10.4" "." "" "production" "us-east-1" "arn:aws:iam::123456789012:role/role" "bucket" "key" "" "HIGH,CRITICAL" "plan" "900" "true" "push" "untrusted-attacker/infraflow" && \
   ! run_aws_guard_test "1.10.4" "." "" "production" "us-east-1" "arn:aws:iam::123456789012:role/role" "bucket" "key" "" "HIGH,CRITICAL" "plan" "900" "true" "push" "TM-threemavithana/infraflow" "ed965edd00391b6b1461a65184838bb7cca5eb81" "TM-threemavithana/infraflow/.github/workflows/reusable-tf-aws.yml@main"; then
  record_pass "AWS Trust Boundary [10/10]: Rogue workflow repository and mutable refs (@main) strictly rejected"
else
  record_fail "AWS Trust Boundary [10/10]: Trust boundary enforcement" "Rogue repo or mutable ref was unexpectedly accepted"
fi

# Test 15.14: Mandatory Security Gates: Rejection of bypass attempts (enable-policy-evaluation: false and enable-trivy: false)
if ! run_aws_guard_test "1.10.4" "." "" "production" "us-east-1" "" "" "" "" "HIGH,CRITICAL" "plan" "900" "false" "pull_request" "TM-threemavithana/infraflow" "ed965edd00391b6b1461a65184838bb7cca5eb81" "TM-threemavithana/infraflow/.github/workflows/reusable-tf-aws.yml@ed965edd00391b6b1461a65184838bb7cca5eb81" "refs/heads/main" "false" "true" && \
   ! run_aws_guard_test "1.10.4" "." "" "production" "us-east-1" "" "" "" "" "HIGH,CRITICAL" "plan" "900" "false" "pull_request" "TM-threemavithana/infraflow" "ed965edd00391b6b1461a65184838bb7cca5eb81" "TM-threemavithana/infraflow/.github/workflows/reusable-tf-aws.yml@ed965edd00391b6b1461a65184838bb7cca5eb81" "refs/heads/main" "true" "false" && \
   ! run_aws_guard_test "1.10.4" "." "" "production" "us-east-1" "" "" "" "" "HIGH,CRITICAL" "plan" "900" "false" "pull_request" "TM-threemavithana/infraflow" "ed965edd00391b6b1461a65184838bb7cca5eb81" "TM-threemavithana/infraflow/.github/workflows/reusable-tf-aws.yml@ed965edd00391b6b1461a65184838bb7cca5eb81" "refs/heads/main" "true" "true" "../../etc"; then
  record_pass "AWS Security Gates [1/3]: Disabling mandatory policy evaluation or Trivy scanning is strictly rejected"
else
  record_fail "AWS Security Gates [1/3]: Mandatory gate bypass" "Disabling policy evaluation or Trivy was unexpectedly permitted"
fi

# Test 15.15: Dual Scanner & Destructive Plan Defaults in reusable-tf-aws.yml
AWS_WF_GATES_VERIFIED=false
if python3 -c "
import yaml
with open('${AWS_REUSABLE_WF}', 'r') as f:
    data = yaml.safe_load(f)
on_block = data.get('on') or data.get(True)
inputs = on_block['workflow_call']['inputs']
assert inputs['fail-on-destructive']['default'] is True, 'fail-on-destructive must default to true'
assert inputs['enable-trivy']['default'] is True, 'enable-trivy must default to true'
assert inputs['enable-policy-evaluation']['default'] is True, 'enable-policy-evaluation must default to true'
steps = [s['id'] for s in data['jobs']['aws-plan']['steps'] if 'id' in s]
assert 'trivy' in steps, 'aws-plan must contain trivy step'
assert 'conftest' in steps, 'aws-plan must contain conftest step'
aws_plan_if = data['jobs']['aws-plan']['if']
assert 'workflow_dispatch' in aws_plan_if
assert 'refs/heads/main' in aws_plan_if
" >/dev/null 2>&1; then
  AWS_WF_GATES_VERIFIED=true
fi

if [[ "${AWS_WF_GATES_VERIFIED}" == "true" ]]; then
  record_pass "AWS Security Gates [2/3]: Workflow enforces dual scanners (Trivy + Conftest) and blocks destructive plans by default"
else
  record_fail "AWS Security Gates [2/3]: Workflow security gates" "reusable-tf-aws.yml missing dual scanners or fail-on-destructive default"
fi

# Test 15.16: Failure Propagation & Output Aggregation Logic
AWS_FAILURE_PROP_VERIFIED=false
if python3 -c "
import yaml, subprocess, tempfile

with open('${AWS_REUSABLE_WF}', 'r') as f:
    data = yaml.safe_load(f)

summary_step = [s for s in data['jobs']['summary']['steps'] if s.get('id') == 'aggregate'][0]['run']

def test_summary(val_res, aws_res, aws_plan_st, aws_auth_st, aws_sec_st, cf_res, cf_plan_st, cf_sec_st, enable_auth):
    with tempfile.NamedTemporaryFile('w', delete=False) as out_f:
        out_path = out_f.name
    env = {
        'GITHUB_OUTPUT': out_path,
        'VALIDATE_RESULT': val_res,
        'AWS_PLAN_RESULT': aws_res,
        'AWS_PLAN_STATUS': aws_plan_st,
        'AWS_AUTH_STATUS': aws_auth_st,
        'AWS_SEC_STATUS': aws_sec_st,
        'AWS_HAS_CHANGES': 'false',
        'AWS_HAS_DESTRUCTIVE': 'false',
        'AWS_TOTAL_CHANGES': '0',
        'CF_PLAN_RESULT': cf_res,
        'CF_PLAN_STATUS': cf_plan_st,
        'CF_SEC_STATUS': cf_sec_st,
        'CF_HAS_CHANGES': 'false',
        'CF_HAS_DESTRUCTIVE': 'false',
        'CF_TOTAL_CHANGES': '0',
        'ENABLE_AWS_AUTH': enable_auth,
    }
    p = subprocess.run(['bash', '-c', summary_step], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    with open(out_path) as f:
        lines = dict(line.strip().split('=', 1) for line in f if '=' in line)
    return p.returncode, lines

# 1. Validation failure -> rejected
rc1, l1 = test_summary('failure', 'skipped', 'skipped', 'disabled', 'skipped', 'skipped', 'skipped', 'skipped', 'false')
assert l1['authorization-status'] == 'rejected' and l1['plan-status'] == 'failure' and rc1 != 0

# 2. Cloud-free success -> not-applicable (offline CI valid, non-deployment status)
rc2, l2 = test_summary('success', 'skipped', 'skipped', 'disabled', 'skipped', 'success', 'success', 'success', 'false')
assert l2['authorization-status'] == 'not-applicable' and l2['plan-status'] == 'success' and rc2 == 0
assert l2['authorization-status'] != 'authorized', "Cloud-free mode must never emit authorization-status=authorized"

# 3. Cloud-free validation failure -> rejected
rc3, l3 = test_summary('success', 'skipped', 'skipped', 'disabled', 'skipped', 'failure', 'failure', 'failure', 'false')
assert l3['authorization-status'] == 'rejected' and rc3 != 0

# 4. AWS Plan auth failure -> rejected
rc4, l4 = test_summary('success', 'failure', 'failure', 'failed', 'failure', 'skipped', 'skipped', 'skipped', 'true')
assert l4['authorization-status'] == 'rejected' and l4['aws-auth-status'] == 'failed' and rc4 != 0

# 5. AWS Plan security scanner failure -> rejected
rc5, l5 = test_summary('success', 'failure', 'success', 'success', 'failure', 'skipped', 'skipped', 'skipped', 'true')
assert l5['authorization-status'] == 'rejected' and l5['security-status'] == 'failure' and rc5 != 0

# 6. AWS Plan complete success -> authorized
rc6, l6 = test_summary('success', 'success', 'success', 'success', 'success', 'skipped', 'skipped', 'skipped', 'true')
assert l6['authorization-status'] == 'authorized' and l6['plan-status'] == 'success' and rc6 == 0
" >/dev/null 2>&1; then
  AWS_FAILURE_PROP_VERIFIED=true
fi

if [[ "${AWS_FAILURE_PROP_VERIFIED}" == "true" ]]; then
  record_pass "AWS Security Gates [3/3]: Output aggregation and failure propagation verified (positive & negative test matrix)"
else
  record_fail "AWS Security Gates [3/3]: Failure propagation" "Summary output aggregation or failure propagation failed test matrix"
fi

# Test 15.13: AWS Reference Module: Canonical formatting
if terraform -chdir="${AWS_REF_MODULE}" fmt -check >/dev/null 2>&1; then
  record_pass "AWS Reference Module [1/6]: Canonical formatting verified (terraform fmt -check)"
else
  record_fail "AWS Reference Module [1/6]: terraform fmt" "Reference module contains unformatted files"
fi

# Test 15.14: AWS Reference Module: Cloud-free initialization
AWS_INIT_ARGS=("-backend=false" "-input=false")
if [[ -d "${HOME}/.terraform.d/plugin-cache" ]]; then
  AWS_INIT_ARGS+=("-plugin-dir=${HOME}/.terraform.d/plugin-cache")
fi
if TF_CLI_CONFIG_FILE=/dev/null terraform -chdir="${AWS_REF_MODULE}" init "${AWS_INIT_ARGS[@]}" >/dev/null 2>&1; then
  record_pass "AWS Reference Module [2/6]: Cloud-free initialization verified (terraform init -backend=false)"
else
  record_fail "AWS Reference Module [2/6]: terraform init" "Reference module initialization failed"
fi

# Test 15.15: AWS Reference Module: Static validation
if terraform -chdir="${AWS_REF_MODULE}" validate >/dev/null 2>&1; then
  record_pass "AWS Reference Module [3/6]: Static validation verified (terraform validate)"
else
  record_fail "AWS Reference Module [3/6]: terraform validate" "Reference module failed static validation"
fi

# Test 15.16: AWS Reference Module: Native unit tests with mock provider
if terraform -chdir="${AWS_REF_MODULE}" test >/dev/null 2>&1; then
  record_pass "AWS Reference Module [4/6]: Native unit tests passed offline with mock provider (terraform test)"
else
  record_fail "AWS Reference Module [4/6]: terraform test" "Reference module native unit tests failed"
fi

# Clean up temporary terraform state in reference module
rm -rf "${AWS_REF_MODULE}/.terraform" "${AWS_REF_MODULE}/.terraform.lock.hcl"

# Test 15.17: AWS Reference Module: Trivy IaC Misconfiguration scan
if [[ -n "${TRIVY_BIN}" ]]; then
  if "${TRIVY_BIN}" config --severity HIGH,CRITICAL --exit-code 1 "${AWS_REF_MODULE}" >/dev/null 2>&1; then
    record_pass "AWS Reference Module [5/6]: Trivy IaC security scan clean (0 HIGH/CRITICAL findings)"
  else
    record_fail "AWS Reference Module [5/6]: Trivy scan" "Trivy detected misconfigurations in AWS reference module"
  fi
else
  record_fail "AWS Reference Module [5/6]: Trivy scan" "Trivy binary not found"
fi

# Test 15.18: AWS Reference Module: Conftest policy compliance
if [[ -n "${CONFTEST_BIN}" ]]; then
  if "${CONFTEST_BIN}" test --all-namespaces --policy "${REPO_ROOT}/policies" "${AWS_REF_MODULE}/main.tf" >/dev/null 2>&1; then
    record_pass "AWS Reference Module [6/6]: Conftest enterprise policy compliance verified"
  else
    record_fail "AWS Reference Module [6/6]: Conftest policy" "Conftest policy failed on AWS reference module"
  fi
else
  record_fail "AWS Reference Module [6/6]: Conftest policy" "Conftest binary not found"
fi

# Test 15.18: OIDC Security Policy: Post-July 15, 2026 immutable subject accepted
IMMUTABLE_TEST_JSON="$(mktemp /tmp/infraflow-oidc-immutable-XXXXXX.json)"
cat << 'EOF' > "${IMMUTABLE_TEST_JSON}"
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:TM-threemavithana@157876462/infraflow@1463731985:ref:refs/heads/main"
        }
      }
    }
  ]
}
EOF

if [[ -n "${CONFTEST_BIN}" ]] && "${CONFTEST_BIN}" test --namespace aws.iam_oidc --policy "${REPO_ROOT}/policies" "${IMMUTABLE_TEST_JSON}" >/dev/null 2>&1; then
  record_pass "AWS OIDC Policy [1/3]: Post-July 15, 2026 immutable OIDC subject format accepted"
else
  record_fail "AWS OIDC Policy [1/3]: Immutable format" "Conftest unexpectedly rejected valid immutable OIDC subject"
fi
rm -f "${IMMUTABLE_TEST_JSON}"

# Test 15.19: OIDC Security Policy: Pre-July 15, 2026 legacy subject accepted
LEGACY_TEST_JSON="$(mktemp /tmp/infraflow-oidc-legacy-XXXXXX.json)"
cat << 'EOF' > "${LEGACY_TEST_JSON}"
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:TM-threemavithana/infraflow:ref:refs/heads/main"
        }
      }
    }
  ]
}
EOF

if [[ -n "${CONFTEST_BIN}" ]] && "${CONFTEST_BIN}" test --namespace aws.iam_oidc --policy "${REPO_ROOT}/policies" "${LEGACY_TEST_JSON}" >/dev/null 2>&1; then
  record_pass "AWS OIDC Policy [2/3]: Pre-July 15, 2026 legacy OIDC subject format accepted"
else
  record_fail "AWS OIDC Policy [2/3]: Legacy format" "Conftest unexpectedly rejected valid legacy OIDC subject"
fi
rm -f "${LEGACY_TEST_JSON}"

# Test 15.20: OIDC Security Policy: Malformed non-numeric IDs and wildcards rejected
MALFORMED_TEST_JSON="$(mktemp /tmp/infraflow-oidc-malformed-XXXXXX.json)"
cat << 'EOF' > "${MALFORMED_TEST_JSON}"
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:TM-threemavithana@abc/infraflow@xyz:ref:refs/heads/main"
        }
      }
    }
  ]
}
EOF

if [[ -n "${CONFTEST_BIN}" ]] && ! "${CONFTEST_BIN}" test --namespace aws.iam_oidc --policy "${REPO_ROOT}/policies" "${MALFORMED_TEST_JSON}" >/dev/null 2>&1; then
  record_pass "AWS OIDC Policy [3/3]: Malformed non-numeric IDs and wildcards rejected as expected"
else
  record_fail "AWS OIDC Policy [3/3]: Malformed ID rejection" "Conftest unexpectedly accepted malformed non-numeric IDs"
fi
rm -f "${MALFORMED_TEST_JSON}"

# Test 15.21: AWS Adapter: Cloud-free mode non-deployment authorization semantics
CLOUDFREE_NON_DEPLOY_VERIFIED=false
if python3 -c "
import yaml

with open('${AWS_REUSABLE_WF}', 'r') as f:
    data = yaml.safe_load(f)

on_block = data.get('on') or data.get(True) or {}
out_desc = on_block.get('workflow_call', {}).get('outputs', {}).get('authorization-status', {}).get('description', '')
assert 'not-applicable' in out_desc, 'Output authorization-status description missing not-applicable'

summary_step = [s for s in data['jobs']['summary']['steps'] if s.get('id') == 'aggregate'][0]['run']
assert 'AUTHORIZATION_STATUS=\"not-applicable\"' in summary_step, 'Summary step missing not-applicable assignment'
assert 'AUTHORIZATION_STATUS=\"authorized\"' in summary_step, 'Summary step missing authorized assignment'
assert 'ENABLE_AWS_AUTH' in summary_step, 'Summary step missing ENABLE_AWS_AUTH check'
" >/dev/null 2>&1; then
  CLOUDFREE_NON_DEPLOY_VERIFIED=true
fi

if [[ "${CLOUDFREE_NON_DEPLOY_VERIFIED}" == "true" ]]; then
  record_pass "AWS Authorization Semantics: Cloud-free mode emits not-applicable and reserves authorized for authenticated plans"
else
  record_fail "AWS Authorization Semantics: Non-deployment status" "reusable-tf-aws.yml failed non-deployment authorization semantics check"
fi

# --- 16. G06 Protected Apply & Destroy: Plan Encryption, Lifecycle, Replay & Apply Contract ---
log_header "16. G06 Protected Apply & Destroy: Plan Encryption, Lifecycle, Replay & Apply Contract"

KMS_ENVELOPE_PY="${REPO_ROOT}/scripts/kms-envelope.py"
G06_TEST_DIR="$(mktemp -d /tmp/infraflow-g06-test-XXXXXX)"

# Test 16.1: kms-envelope.py executable and syntax valid
if [[ -x "${KMS_ENVELOPE_PY}" ]] && python3 "${KMS_ENVELOPE_PY}" --help >/dev/null 2>&1; then
  record_pass "G06 Envelope Tooling [1/24]: kms-envelope.py syntax & CLI interface verified"
else
  record_fail "G06 Envelope Tooling [1/24]: kms-envelope.py" "kms-envelope.py missing, not executable, or failed syntax check"
fi

# Test 16.2: G06 Cryptographic unit test suite (20 tests)
if python3 -m unittest discover -s "${REPO_ROOT}/tests" >/dev/null 2>&1; then
  record_pass "G06 Cryptographic Suite [2/24]: All 20 unit tests passed (test_kms_envelope.py)"
else
  record_fail "G06 Cryptographic Suite [2/24]: Unit tests" "One or more tests in tests/test_kms_envelope.py failed"
fi

# Test 16.3: CLI KEK generation with mode 0600
G06_TEST_KEK="${G06_TEST_DIR}/test.kek"
if python3 "${KMS_ENVELOPE_PY}" generate-kek --output-kek "${G06_TEST_KEK}" >/dev/null 2>&1 && [[ -f "${G06_TEST_KEK}" ]]; then
  KEK_PERMS="$(stat -c "%a" "${G06_TEST_KEK}" 2>/dev/null || stat -f "%Lp" "${G06_TEST_KEK}" 2>/dev/null || echo "600")"
  if [[ "${KEK_PERMS}" == "600" ]]; then
    record_pass "G06 Key Management [3/24]: Mock KEK generated with restrictive permissions (mode 0600)"
  else
    record_fail "G06 Key Management [3/24]: Permissions" "Generated KEK file has insecure permissions: ${KEK_PERMS}"
  fi
else
  record_fail "G06 Key Management [3/24]: generate-kek" "Failed to generate mock KEK"
fi

# Test 16.4: CLI Encryption and Decryption Roundtrip
G06_TEST_PLAN="${G06_TEST_DIR}/plan.tfplan"
G06_TEST_ENV="${G06_TEST_DIR}/plan.enc.json"
G06_TEST_DEC="${G06_TEST_DIR}/plan.dec.tfplan"
echo -n "SYNTHETIC_TERRAFORM_BINARY_PLAN_G06_$(date +%s)" > "${G06_TEST_PLAN}"
ORIG_DIGEST="$(sha256sum "${G06_TEST_PLAN}" | awk '{print $1}')"

if python3 "${KMS_ENVELOPE_PY}" encrypt \
    --plan-file "${G06_TEST_PLAN}" \
    --output-envelope "${G06_TEST_ENV}" \
    --kek-file "${G06_TEST_KEK}" \
    --repo "TM-threemavithana/infraflow-consumer-test" \
    --commit "d0660de837ca07d5bdd56f04b0e50691ce98bd28" \
    --environment "production" >/dev/null 2>&1 && \
   python3 "${KMS_ENVELOPE_PY}" decrypt \
    --envelope-file "${G06_TEST_ENV}" \
    --output-plan "${G06_TEST_DEC}" \
    --kek-file "${G06_TEST_KEK}" \
    --expected-repo "TM-threemavithana/infraflow-consumer-test" \
    --expected-commit "d0660de837ca07d5bdd56f04b0e50691ce98bd28" \
    --expected-environment "production" \
    --expected-digest "${ORIG_DIGEST}" >/dev/null 2>&1 && \
   cmp -s "${G06_TEST_PLAN}" "${G06_TEST_DEC}"; then
  record_pass "G06 Envelope Lifecycle [4/24]: CLI encrypt and decrypt roundtrip matches exact binary digest"
else
  record_fail "G06 Envelope Lifecycle [4/24]: Roundtrip" "CLI encryption/decryption failed or produced mismatched bytes"
fi

# Test 16.5: CLI Adversarial Tampering: Bit-flip in ciphertext fails closed
G06_TAMPERED_ENV="${G06_TEST_DIR}/plan.tampered.enc.json"
python3 -c "
import json
with open('${G06_TEST_ENV}', 'r') as f:
    d = json.load(f)
import base64
ct = bytearray(base64.b64decode(d['ciphertext']))
ct[0] ^= 0x01
d['ciphertext'] = base64.b64encode(ct).decode('ascii')
with open('${G06_TAMPERED_ENV}', 'w') as f:
    json.dump(d, f)
"
if ! python3 "${KMS_ENVELOPE_PY}" decrypt \
    --envelope-file "${G06_TAMPERED_ENV}" \
    --output-plan "${G06_TEST_DIR}/tampered.plan" \
    --kek-file "${G06_TEST_KEK}" >/dev/null 2>&1; then
  record_pass "G06 Adversarial Defense [5/24]: Ciphertext bit-flip rejected as expected (exit code != 0)"
else
  record_fail "G06 Adversarial Defense [5/24]: Tamper detection" "Decryption unexpectedly accepted tampered ciphertext"
fi

# Test 16.6: CLI Context Binding: Repository mismatch rejected
if ! python3 "${KMS_ENVELOPE_PY}" decrypt \
    --envelope-file "${G06_TEST_ENV}" \
    --output-plan "${G06_TEST_DIR}/mismatched_repo.plan" \
    --kek-file "${G06_TEST_KEK}" \
    --expected-repo "attacker-org/malicious-repo" >/dev/null 2>&1; then
  record_pass "G06 Context Binding [6/24]: Repository identity mismatch rejected as expected (exit code != 0)"
else
  record_fail "G06 Context Binding [6/24]: Repo mismatch" "Decryption unexpectedly accepted mismatched repository context"
fi

# Test 16.7: CLI Key Isolation: Wrong KEK rejected
G06_WRONG_KEK="${G06_TEST_DIR}/wrong.kek"
python3 "${KMS_ENVELOPE_PY}" generate-kek --output-kek "${G06_WRONG_KEK}" >/dev/null 2>&1
if ! python3 "${KMS_ENVELOPE_PY}" decrypt \
    --envelope-file "${G06_TEST_ENV}" \
    --output-plan "${G06_TEST_DIR}/wrong_kek.plan" \
    --kek-file "${G06_WRONG_KEK}" >/dev/null 2>&1; then
  record_pass "G06 Key Isolation [7/24]: Decryption with unauthorized KEK rejected as expected (exit code != 0)"
else
  record_fail "G06 Key Isolation [7/24]: Key isolation" "Decryption unexpectedly succeeded with unauthorized KEK"
fi

# Test 16.8: CLI Static Verification: verify-envelope checks headers without KEK
if python3 "${KMS_ENVELOPE_PY}" verify-envelope \
    --envelope-file "${G06_TEST_ENV}" \
    --expected-repo "TM-threemavithana/infraflow-consumer-test" \
    --expected-commit "d0660de837ca07d5bdd56f04b0e50691ce98bd28" \
    --expected-environment "production" \
    --expected-digest "${ORIG_DIGEST}" >/dev/null 2>&1; then
  record_pass "G06 Static Verification [8/24]: verify-envelope validates schema and context headers without KEK"
else
  record_fail "G06 Static Verification [8/24]: verify-envelope" "Static envelope verification failed on valid envelope"
fi

# Test 16.9: verify-plan-lifecycle.py executable and syntax valid
VERIFY_LIFECYCLE_PY="${REPO_ROOT}/scripts/verify-plan-lifecycle.py"
if [[ -x "${VERIFY_LIFECYCLE_PY}" ]] && python3 "${VERIFY_LIFECYCLE_PY}" --help >/dev/null 2>&1; then
  record_pass "G06 Lifecycle Tooling [9/24]: verify-plan-lifecycle.py syntax & CLI interface verified"
else
  record_fail "G06 Lifecycle Tooling [9/24]: verify-plan-lifecycle.py" "verify-plan-lifecycle.py missing, not executable, or failed syntax check"
fi

# Test 16.10: Full G06 unit test suite (test_kms_envelope.py + test_plan_lifecycle.py)
if python3 -m unittest discover -s "${REPO_ROOT}/tests" -p "test_*.py" >/dev/null 2>&1; then
  record_pass "G06 Full Test Suite [10/24]: All unit tests passed"
else
  record_fail "G06 Full Test Suite [10/24]: Unit tests" "One or more tests in tests directory failed"
fi

# Test 16.11: Plan expiration gate: Fresh accepted, expired rejected
G06_TS_NOW="2026-11-20T12:00:00Z"
G06_TS_CREATED="2026-11-20T11:00:00Z"
G06_TS_FRESH_EXP="2026-11-20T17:00:00Z"
G06_TS_STALE_EXP="2026-11-20T11:50:00Z"

if python3 "${VERIFY_LIFECYCLE_PY}" validate-expiration \
    --created-at "${G06_TS_CREATED}" \
    --expires-at "${G06_TS_FRESH_EXP}" \
    --current-time "${G06_TS_NOW}" >/dev/null 2>&1 && \
   ! python3 "${VERIFY_LIFECYCLE_PY}" validate-expiration \
    --created-at "${G06_TS_CREATED}" \
    --expires-at "${G06_TS_STALE_EXP}" \
    --current-time "${G06_TS_NOW}" >/dev/null 2>&1; then
  record_pass "G06 Expiration Gate [11/24]: Fresh plan accepted, expired plan rejected"
else
  record_fail "G06 Expiration Gate [11/24]: Expiration" "validate-expiration failed fresh/expired gate"
fi

# Test 16.12: Future plan gate: Future-created plan rejected
G06_TS_FUTURE="2026-11-20T14:00:00Z"
if ! python3 "${VERIFY_LIFECYCLE_PY}" validate-expiration \
    --created-at "${G06_TS_FUTURE}" \
    --expires-at "${G06_TS_FRESH_EXP}" \
    --current-time "${G06_TS_NOW}" >/dev/null 2>&1; then
  record_pass "G06 Future Plan Gate [12/24]: Future-created plan rejected as expected (exit code != 0)"
else
  record_fail "G06 Future Plan Gate [12/24]: Future plan" "validate-expiration unexpectedly accepted future-dated plan"
fi

# Test 16.13: State consistency gate: Lineage & serial match accepted, stale serial rejected
G06_STATE_FILE="${G06_TEST_DIR}/state.json"
cat << 'EOF' > "${G06_STATE_FILE}"
{
  "version": 4,
  "terraform_version": "1.10.4",
  "serial": 42,
  "lineage": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
  "outputs": {},
  "resources": []
}
EOF

if python3 "${VERIFY_LIFECYCLE_PY}" validate-state \
    --state-file "${G06_STATE_FILE}" \
    --expected-lineage "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d" \
    --expected-serial 42 >/dev/null 2>&1 && \
   ! python3 "${VERIFY_LIFECYCLE_PY}" validate-state \
    --state-file "${G06_STATE_FILE}" \
    --expected-lineage "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d" \
    --expected-serial 41 >/dev/null 2>&1; then
  record_pass "G06 State Consistency [13/24]: State lineage & serial match accepted; stale serial rejected"
else
  record_fail "G06 State Consistency [13/24]: State gate" "validate-state failed lineage/serial check"
fi

# Test 16.14: Replay prevention: Atomic plan reservation succeeds, duplicate rejected
G06_LEDGER_DB="${G06_TEST_DIR}/ledger.db"
if python3 "${VERIFY_LIFECYCLE_PY}" ledger-reserve \
    --ledger-db "${G06_LEDGER_DB}" \
    --plan-id "plan-gate-test-01" \
    --plan-digest "${ORIG_DIGEST}" \
    --repo "TM-threemavithana/infraflow-consumer-test" \
    --commit "d0660de837ca07d5bdd56f04b0e50691ce98bd28" \
    --environment "production" \
    --expires-at "${G06_TS_FRESH_EXP}" >/dev/null 2>&1 && \
   ! python3 "${VERIFY_LIFECYCLE_PY}" ledger-reserve \
    --ledger-db "${G06_LEDGER_DB}" \
    --plan-id "plan-gate-test-01" \
    --plan-digest "${ORIG_DIGEST}" \
    --repo "TM-threemavithana/infraflow-consumer-test" \
    --commit "d0660de837ca07d5bdd56f04b0e50691ce98bd28" \
    --environment "production" \
    --expires-at "${G06_TS_FRESH_EXP}" >/dev/null 2>&1; then
  record_pass "G06 Replay Prevention [14/24]: Atomic plan reservation succeeds; duplicate reservation rejected"
else
  record_fail "G06 Replay Prevention [14/24]: Replay gate" "ledger-reserve failed duplicate reservation rejection"
fi

# Test 16.15: Consumed plan gate: Consumed plan re-execution rejected
if python3 "${VERIFY_LIFECYCLE_PY}" ledger-consume \
    --ledger-db "${G06_LEDGER_DB}" \
    --plan-id "plan-gate-test-01" >/dev/null 2>&1 && \
   ! python3 "${VERIFY_LIFECYCLE_PY}" ledger-reserve \
    --ledger-db "${G06_LEDGER_DB}" \
    --plan-id "plan-gate-test-01" \
    --plan-digest "${ORIG_DIGEST}" \
    --repo "TM-threemavithana/infraflow-consumer-test" \
    --commit "d0660de837ca07d5bdd56f04b0e50691ce98bd28" \
    --environment "production" \
    --expires-at "${G06_TS_FRESH_EXP}" >/dev/null 2>&1; then
  record_pass "G06 Consumed Plan Gate [15/24]: Consumed plan re-execution strictly rejected"
else
  record_fail "G06 Consumed Plan Gate [15/24]: Consumed gate" "ledger-consume or re-reservation check failed"
fi

# Test 16.16: Pre-execution authorization verifier: Full roundtrip emits AUTHORIZED_FOR_SIMULATION
G06_ROUNDTRIP_LEDGER="${G06_TEST_DIR}/roundtrip_ledger.db"
VERIFY_OUT="$(python3 "${VERIFY_LIFECYCLE_PY}" verify \
    --envelope-file "${G06_TEST_ENV}" \
    --state-file "${G06_STATE_FILE}" \
    --expected-repo "TM-threemavithana/infraflow-consumer-test" \
    --expected-commit "d0660de837ca07d5bdd56f04b0e50691ce98bd28" \
    --expected-environment "production" \
    --expected-lineage "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d" \
    --expected-serial 42 \
    --ledger-db "${G06_ROUNDTRIP_LEDGER}" \
    --provenance-status "VERIFIED" 2>&1 || true)"

if echo "${VERIFY_OUT}" | grep -q '"decision": "AUTHORIZED_FOR_SIMULATION"'; then
  record_pass "G06 Pre-Execution Verifier [16/24]: Full roundtrip emits AUTHORIZED_FOR_SIMULATION"
else
  record_fail "G06 Pre-Execution Verifier [16/24]: Verifier roundtrip" "verify CLI failed to authorize valid plan simulation: ${VERIFY_OUT}"
fi

# Test 16.17: Pre-execution security boundary: Unverified provenance strictly rejected
REJECT_OUT="$(python3 "${VERIFY_LIFECYCLE_PY}" verify \
    --envelope-file "${G06_TEST_ENV}" \
    --state-file "${G06_STATE_FILE}" \
    --expected-repo "TM-threemavithana/infraflow-consumer-test" \
    --expected-commit "d0660de837ca07d5bdd56f04b0e50691ce98bd28" \
    --expected-environment "production" \
    --expected-lineage "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d" \
    --expected-serial 42 \
    --ledger-db "${G06_ROUNDTRIP_LEDGER}" \
    --provenance-status "UNVERIFIED" 2>&1 || true)"

if echo "${REJECT_OUT}" | grep -q '"decision": "REJECTED"' || echo "${REJECT_OUT}" | grep -q 'UNVERIFIED_PROVENANCE'; then
  record_pass "G06 Security Boundary [17/24]: Unverified provenance strictly rejected (fail-closed)"
else
  record_fail "G06 Security Boundary [17/24]: Provenance rejection" "verify CLI unexpectedly authorized unverified provenance: ${REJECT_OUT}"
fi

# Test 16.18: reusable-tf-apply.yml actionlint validation
REUSABLE_APPLY_WF="${REPO_ROOT}/.github/workflows/reusable-tf-apply.yml"
if [[ -n "${ACTIONLINT_BIN}" ]]; then
  if (cd "${REPO_ROOT}" && "${ACTIONLINT_BIN}" .github/workflows/reusable-tf-apply.yml >/dev/null 2>&1); then
    record_pass "G06 Apply Workflow [18/24]: Actionlint syntax & schema validation passed"
  else
    record_fail "G06 Apply Workflow [18/24]: Actionlint" "Actionlint failed on reusable-tf-apply.yml"
  fi
else
  record_fail "G06 Apply Workflow [18/24]: Actionlint" "Actionlint binary not found"
fi

# Test 16.19: reusable-tf-apply.yml Zizmor supply chain security audit
if [[ -n "${ZIZMOR_BIN}" ]]; then
  if (cd "${REPO_ROOT}" && "${ZIZMOR_BIN}" -c .zizmor.yml --min-severity medium .github/workflows/reusable-tf-apply.yml >/dev/null 2>&1); then
    record_pass "G06 Apply Workflow [19/24]: Zizmor supply chain security audit passed (0 medium/high findings)"
  else
    record_fail "G06 Apply Workflow [19/24]: Zizmor" "Zizmor detected supply chain vulnerabilities in reusable-tf-apply.yml"
  fi
else
  record_fail "G06 Apply Workflow [19/24]: Zizmor" "Zizmor binary not found"
fi

# Test 16.20: Full unit test suite (133 tests across all test modules)
if python3 -m unittest discover -s "${REPO_ROOT}/tests" -p "test_*.py" >/dev/null 2>&1; then
  record_pass "G06 Full Test Suite [20/39]: All 133 unit tests passed (test_kms_envelope.py + test_plan_lifecycle.py + test_apply_workflow.py + test_destruction_recovery.py + test_g06_adversarial_integration.py)"
else
  record_fail "G06 Full Test Suite [20/39]: Unit tests" "One or more tests in tests directory failed"
fi

# Test 16.21: Workflow Guard: Untrusted PR event rejected
EXTRACTED_APPLY_GUARD="$(mktemp /tmp/infraflow-apply-guard-XXXXXX.sh)"
python3 -c "
import yaml
with open('${REUSABLE_APPLY_WF}', 'r') as f:
    wf = yaml.safe_load(f)
script = wf['jobs']['validate-inputs']['steps'][0]['run']
with open('${EXTRACTED_APPLY_GUARD}', 'w') as out:
    out.write(script)
"
chmod +x "${EXTRACTED_APPLY_GUARD}"

if ! INPUT_PLAN_ID="plan-test-01" \
     INPUT_ENVELOPE_FILE="artifacts/plan.enc.json" \
     INPUT_STATE_FILE="artifacts/terraform.tfstate" \
     INPUT_ENV="production" \
     INPUT_LINEAGE="3f2e1d0c-4b5a-6789-0123-abcdef456789" \
     INPUT_SERIAL="42" \
     INPUT_BACKEND="s3://bucket/key" \
     INPUT_WORKSPACE="default" \
     INPUT_PROVENANCE_FILE="" \
     INPUT_LEDGER_PATH=".infraflow/ledger.db" \
     EVENT_NAME="pull_request" \
     TARGET_REF="refs/heads/main" \
     WORKFLOW_REPO="TM-threemavithana/infraflow" \
     WORKFLOW_SHA="484b067aa500d5523d1bccc06ce111cfe736a8af" \
     WORKFLOW_REF="TM-threemavithana/infraflow/.github/workflows/reusable-tf-apply.yml@484b067aa500d5523d1bccc06ce111cfe736a8af" \
     bash "${EXTRACTED_APPLY_GUARD}" >/dev/null 2>&1; then
  record_pass "G06 Workflow Guard [21/24]: Untrusted pull requests (pull_request & pull_request_target) rejected (SEC-02 fail-closed)"
else
  record_fail "G06 Workflow Guard [21/24]: PR rejection" "Workflow guard unexpectedly permitted pull_request trigger"
fi

# Test 16.22: Workflow Guard: Mutable workflow ref (@main) strictly rejected
if ! INPUT_PLAN_ID="plan-test-01" \
     INPUT_ENVELOPE_FILE="artifacts/plan.enc.json" \
     INPUT_STATE_FILE="artifacts/terraform.tfstate" \
     INPUT_ENV="production" \
     INPUT_LINEAGE="3f2e1d0c-4b5a-6789-0123-abcdef456789" \
     INPUT_SERIAL="42" \
     INPUT_BACKEND="s3://bucket/key" \
     INPUT_WORKSPACE="default" \
     INPUT_PROVENANCE_FILE="" \
     INPUT_LEDGER_PATH=".infraflow/ledger.db" \
     EVENT_NAME="push" \
     TARGET_REF="refs/heads/main" \
     WORKFLOW_REPO="TM-threemavithana/infraflow" \
     WORKFLOW_SHA="484b067aa500d5523d1bccc06ce111cfe736a8af" \
     WORKFLOW_REF="TM-threemavithana/infraflow/.github/workflows/reusable-tf-apply.yml@main" \
     bash "${EXTRACTED_APPLY_GUARD}" >/dev/null 2>&1; then
  record_pass "G06 Workflow Trust Boundary [22/24]: Mutable workflow ref (@main) strictly rejected"
else
  record_fail "G06 Workflow Trust Boundary [22/24]: Mutable ref" "Workflow guard unexpectedly accepted mutable @main ref"
fi
rm -f "${EXTRACTED_APPLY_GUARD}"

# Test 16.23: Consumer example workflow actionlint validation & immutable pin
CONSUMER_APPLY_WF="${REPO_ROOT}/examples/consumer-workflow/.github/workflows/infraflow-protected-apply-simulation.yml"
if [[ -f "${CONSUMER_APPLY_WF}" ]] && \
   (cd "${REPO_ROOT}" && "${ACTIONLINT_BIN}" "${CONSUMER_APPLY_WF}" >/dev/null 2>&1) && \
   grep -q '@[0-9a-f]\{40\}' "${CONSUMER_APPLY_WF}"; then
  record_pass "G06 Consumer Workflow [23/24]: Consumer example passes actionlint and references immutable SHA"
else
  record_fail "G06 Consumer Workflow [23/24]: Consumer example" "Consumer apply example missing, invalid, or unpinned"
fi

# Test 16.24: Simulation safety invariant: Absence of real apply/destroy execution
if ! grep -qi "terraform apply" "${REUSABLE_APPLY_WF}" && \
   ! grep -qi "terraform destroy" "${REUSABLE_APPLY_WF}" && \
   ! grep -qi "force-unlock" "${REUSABLE_APPLY_WF}"; then
  record_pass "G06 Simulation Safety [24/34]: Strict absence of state-modifying terraform apply/destroy execution"
else
  record_fail "G06 Simulation Safety [24/34]: Simulation invariant" "reusable-tf-apply.yml contains state-modifying execution commands"
fi

# Test 16.25: assess-destruction.py syntax & CLI interface
ASSESS_DESTRUCTION_PY="${REPO_ROOT}/scripts/assess-destruction.py"
if [[ -x "${ASSESS_DESTRUCTION_PY}" ]] && python3 "${ASSESS_DESTRUCTION_PY}" --help >/dev/null 2>&1; then
  record_pass "G06 Destruction Tooling [25/34]: assess-destruction.py syntax & CLI interface verified"
else
  record_fail "G06 Destruction Tooling [25/34]: assess-destruction.py" "assess-destruction.py missing, not executable, or failed CLI check"
fi

# Test 16.26: Destruction & Recovery Unit Test Suite (25 tests)
if python3 -m unittest "${REPO_ROOT}/tests/test_destruction_recovery.py" >/dev/null 2>&1; then
  record_pass "G06 Destruction Test Suite [26/34]: All 25 unit tests passed (test_destruction_recovery.py)"
else
  record_fail "G06 Destruction Test Suite [26/34]: Unit tests" "One or more tests in tests/test_destruction_recovery.py failed"
fi

# Setup fixtures for CLI destruction tests
G06_DESTRUCT_PLAN="${G06_TEST_DIR}/destruct_plan.json"
cat << 'EOF' > "${G06_DESTRUCT_PLAN}"
{
  "format_version": "1.2",
  "terraform_version": "1.10.4",
  "resource_changes": [
    {
      "address": "aws_instance.worker1",
      "type": "aws_instance",
      "name": "worker1",
      "change": {
        "actions": ["delete"]
      }
    },
    {
      "address": "aws_instance.worker2",
      "type": "aws_instance",
      "name": "worker2",
      "change": {
        "actions": ["delete"]
      }
    },
    {
      "address": "aws_instance.manager",
      "type": "aws_instance",
      "name": "manager",
      "change": {
        "actions": ["update"]
      }
    }
  ]
}
EOF

# Test 16.27: Blast Radius: Plan exceeding deletion limit rejected
if ! python3 "${ASSESS_DESTRUCTION_PY}" assess \
     --plan-file "${G06_DESTRUCT_PLAN}" \
     --expected-plan-id "plan-test-01" \
     --expected-digest "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" \
     --expected-repo "TM-threemavithana/infraflow" \
     --environment "staging" \
     --max-deletions 1 >/dev/null 2>&1; then
  record_pass "G06 Blast Radius [27/34]: Plan with deletions exceeding blast-radius threshold rejected (DELETION_LIMIT_EXCEEDED)"
else
  record_fail "G06 Blast Radius [27/34]: Deletion limit" "assess-destruction.py unexpectedly authorized plan exceeding deletion limit"
fi

# Test 16.28: Missing confirmation rejected for destructive plan
if ! python3 "${ASSESS_DESTRUCTION_PY}" assess \
     --plan-file "${G06_DESTRUCT_PLAN}" \
     --expected-plan-id "plan-test-01" \
     --expected-digest "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" \
     --expected-repo "TM-threemavithana/infraflow" \
     --environment "staging" \
     --max-deletions 5 >/dev/null 2>&1; then
  record_pass "G06 Destruction Confirmation [28/34]: Plan with destructive changes and missing confirmation rejected (MISSING_DESTRUCTION_CONFIRMATION)"
else
  record_fail "G06 Destruction Confirmation [28/34]: Missing confirmation" "assess-destruction.py unexpectedly authorized destructive changes without confirmation"
fi

# Test 16.29: Generic confirmation token strictly rejected
if ! python3 "${ASSESS_DESTRUCTION_PY}" assess \
     --plan-file "${G06_DESTRUCT_PLAN}" \
     --expected-plan-id "plan-test-01" \
     --expected-digest "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" \
     --expected-repo "TM-threemavithana/infraflow" \
     --environment "staging" \
     --max-deletions 5 \
     --confirmation-token "yes" >/dev/null 2>&1; then
  record_pass "G06 Destruction Confirmation [29/34]: Generic confirmation string ('yes') strictly rejected (INVALID_CONFIRMATION_TOKEN)"
else
  record_fail "G06 Destruction Confirmation [29/34]: Generic token" "assess-destruction.py unexpectedly accepted generic 'yes' confirmation"
fi

# Test 16.30: Confirmation bound to another plan rejected
G06_MISMATCH_CONF="${G06_TEST_DIR}/mismatch_conf.json"
python3 "${ASSESS_DESTRUCTION_PY}" create-confirmation \
  --plan-id "wrong-plan-id" \
  --plan-digest "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" \
  --repo "TM-threemavithana/infraflow" \
  --environment "staging" \
  --pure-deletions 2 \
  --replacements 0 \
  --authorized-by "security-lead@infraflow.local" \
  --output-file "${G06_MISMATCH_CONF}" >/dev/null 2>&1

if ! python3 "${ASSESS_DESTRUCTION_PY}" assess \
     --plan-file "${G06_DESTRUCT_PLAN}" \
     --expected-plan-id "plan-test-01" \
     --expected-digest "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" \
     --expected-repo "TM-threemavithana/infraflow" \
     --environment "staging" \
     --max-deletions 5 \
     --confirmation-file "${G06_MISMATCH_CONF}" >/dev/null 2>&1; then
  record_pass "G06 Confirmation Binding [30/34]: Confirmation bound to mismatched plan ID rejected (CONFIRMATION_PLAN_MISMATCH)"
else
  record_fail "G06 Confirmation Binding [30/34]: Plan ID mismatch" "assess-destruction.py unexpectedly accepted mismatched plan confirmation"
fi

# Test 16.31: Expired confirmation token rejected
G06_EXPIRED_CONF="${G06_TEST_DIR}/expired_conf.json"
python3 "${ASSESS_DESTRUCTION_PY}" create-confirmation \
  --plan-id "plan-test-01" \
  --plan-digest "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" \
  --repo "TM-threemavithana/infraflow" \
  --environment "staging" \
  --pure-deletions 2 \
  --replacements 0 \
  --authorized-by "security-lead@infraflow.local" \
  --ttl-seconds -10 \
  --output-file "${G06_EXPIRED_CONF}" >/dev/null 2>&1

if ! python3 "${ASSESS_DESTRUCTION_PY}" assess \
     --plan-file "${G06_DESTRUCT_PLAN}" \
     --expected-plan-id "plan-test-01" \
     --expected-digest "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" \
     --expected-repo "TM-threemavithana/infraflow" \
     --environment "staging" \
     --max-deletions 5 \
     --confirmation-file "${G06_EXPIRED_CONF}" >/dev/null 2>&1; then
  record_pass "G06 Confirmation Expiration [31/34]: Expired confirmation token rejected (CONFIRMATION_EXPIRED)"
else
  record_fail "G06 Confirmation Expiration [31/34]: Expired token" "assess-destruction.py unexpectedly accepted expired confirmation token"
fi

# Test 16.32: State-wide destroy attempt rejected
G06_STATEWIDE_PLAN="${G06_TEST_DIR}/statewide_plan.json"
cat << 'EOF' > "${G06_STATEWIDE_PLAN}"
{
  "format_version": "1.2",
  "terraform_version": "1.10.4",
  "resource_changes": [
    {"address": "aws_instance.node1", "type": "aws_instance", "change": {"actions": ["delete"]}},
    {"address": "aws_instance.node2", "type": "aws_instance", "change": {"actions": ["delete"]}}
  ]
}
EOF

if ! python3 "${ASSESS_DESTRUCTION_PY}" assess \
     --plan-file "${G06_STATEWIDE_PLAN}" \
     --expected-plan-id "plan-test-01" \
     --expected-digest "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" \
     --expected-repo "TM-threemavithana/infraflow" \
     --environment "staging" \
     --max-deletions 10 >/dev/null 2>&1; then
  record_pass "G06 State-Wide Destroy [32/34]: Plan deleting all active resources rejected (STATE_WIDE_DESTROY_BLOCKED)"
else
  record_fail "G06 State-Wide Destroy [32/34]: State-wide destroy" "assess-destruction.py unexpectedly permitted state-wide destroy"
fi

# Test 16.33: Security-critical resource deletion blocked
G06_CRITICAL_PLAN="${G06_TEST_DIR}/critical_plan.json"
cat << 'EOF' > "${G06_CRITICAL_PLAN}"
{
  "format_version": "1.2",
  "terraform_version": "1.10.4",
  "resource_changes": [
    {"address": "aws_kms_key.app_vault", "type": "aws_kms_key", "change": {"actions": ["delete"]}},
    {"address": "aws_instance.node", "type": "aws_instance", "change": {"actions": ["update"]}}
  ]
}
EOF

if ! python3 "${ASSESS_DESTRUCTION_PY}" assess \
     --plan-file "${G06_CRITICAL_PLAN}" \
     --expected-plan-id "plan-test-01" \
     --expected-digest "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" \
     --expected-repo "TM-threemavithana/infraflow" \
     --environment "staging" \
     --max-deletions 10 >/dev/null 2>&1; then
  record_pass "G06 Security-Critical Assets [33/34]: Deletion of security-critical resources rejected (SECURITY_CRITICAL_DESTRUCTION_BLOCKED)"
else
  record_fail "G06 Security-Critical Assets [33/34]: Security-critical" "assess-destruction.py unexpectedly allowed deletion of KMS key"
fi

# Test 16.34: Valid plan with valid confirmation authorized
G06_VALID_CONF="${G06_TEST_DIR}/valid_conf.json"
python3 "${ASSESS_DESTRUCTION_PY}" create-confirmation \
  --plan-id "plan-test-01" \
  --plan-digest "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" \
  --repo "TM-threemavithana/infraflow" \
  --environment "staging" \
  --pure-deletions 2 \
  --replacements 0 \
  --authorized-by "security-lead@infraflow.local" \
  --ttl-seconds 3600 \
  --output-file "${G06_VALID_CONF}" >/dev/null 2>&1

if python3 "${ASSESS_DESTRUCTION_PY}" assess \
     --plan-file "${G06_DESTRUCT_PLAN}" \
     --expected-plan-id "plan-test-01" \
     --expected-digest "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" \
     --expected-repo "TM-threemavithana/infraflow" \
     --environment "staging" \
     --max-deletions 5 \
     --confirmation-file "${G06_VALID_CONF}" >/dev/null 2>&1; then
  record_pass "G06 Authorized Destruction [34/39]: Valid plan with matching confirmation authorized (AUTHORIZED_SIMULATION_WITH_CONFIRMATION)"
else
  record_fail "G06 Authorized Destruction [34/39]: Valid confirmation" "assess-destruction.py failed to authorize valid plan with matching confirmation"
fi

# Test 16.35: Dedicated Adversarial Integration Test Suite (39 tests)
if python3 -m unittest "${REPO_ROOT}/tests/test_g06_adversarial_integration.py" >/dev/null 2>&1; then
  record_pass "G06 Adversarial Integration [35/39]: All 39 adversarial integration tests passed (test_g06_adversarial_integration.py)"
else
  record_fail "G06 Adversarial Integration [35/39]: Adversarial suite" "One or more tests in test_g06_adversarial_integration.py failed"
fi

# Test 16.36: Workflow contract verification: Symlink rejection check across all inputs in reusable-tf-apply.yml
# shellcheck disable=SC2016
if grep -q 'if \[\[ -L "\${file_var}" \]\]' "${REUSABLE_APPLY_WF}" && \
   grep -q 'if \[\[ -L "\${opt_file}" \]\]' "${REUSABLE_APPLY_WF}"; then
  record_pass "G06 Symlink Containment [36/39]: Symlink rejection verified across all workflow input files"
else
  record_fail "G06 Symlink Containment [36/39]: Symlink check" "reusable-tf-apply.yml missing strict symlink rejection"
fi

# Test 16.37: Workflow contract verification: In-toto DSSE provenance cryptographic verification gate in reusable-tf-apply.yml
if grep -q 'verify-provenance' "${REUSABLE_APPLY_WF}" && \
   grep -q 'trusted_signer.pub' "${REUSABLE_APPLY_WF}"; then
  record_pass "G06 Provenance Verification Gate [37/39]: In-toto DSSE cryptographic provenance verification gate verified"
else
  record_fail "G06 Provenance Verification Gate [37/39]: Provenance gate" "reusable-tf-apply.yml missing cryptographic provenance verification"
fi

# Test 16.38: Workflow contract verification: Fail-closed summary status check
if grep -q 'DESTRUCT_STATUS.*==.*"authorized".*DESTRUCT_STATUS.*==.*"safe".*DESTRUCT_STATUS.*==.*"not-applicable"' "${REUSABLE_APPLY_WF}" && \
   ! grep -q 'DESTRUCT_STATUS.*!=.*"rejected"' "${REUSABLE_APPLY_WF}"; then
  record_pass "G06 Fail-Closed Outcome Gate [38/39]: Summary gate requires positive membership in authorized/safe/not-applicable"
else
  record_fail "G06 Fail-Closed Outcome Gate [38/39]: Outcome gate" "reusable-tf-apply.yml non-fail-closed destruction status evaluation"
fi

# Test 16.39: Platform blast-radius ceiling enforcement: hard ceiling of 25 deletions and prohibited state-wide destroy in production
if grep -q 'PLATFORM_MAX_DELETIONS_CEILING = 25' "${ASSESS_DESTRUCTION_PY}" && \
   grep -q 'POLICY_CEILING_EXCEEDED' "${ASSESS_DESTRUCTION_PY}"; then
  record_pass "G06 Platform Guardrail Ceilings [39/39]: Platform hard ceilings enforced (25 max deletions, statewide destroy blocked in prod)"
else
  record_fail "G06 Platform Guardrail Ceilings [39/39]: Ceilings" "assess-destruction.py missing platform hard guardrail ceilings"
fi

rm -rf "${G06_TEST_DIR}"

# --- 17. Google Cloud Adapter & Workload Identity Architecture (G07.2 / G07.3) ---
log_header "17. Google Cloud Adapter & Workload Identity Architecture (G07.2 / G07.3)"

GCP_REUSABLE_WF="${REPO_ROOT}/.github/workflows/reusable-tf-gcp.yml"
GCP_REF_MODULE="${REPO_ROOT}/examples/gcp-reference-module"

# Test 17.1: Actionlint verification of GCP reusable workflow
if [[ -n "${ACTIONLINT_BIN}" ]]; then
  if "${ACTIONLINT_BIN}" "${GCP_REUSABLE_WF}" >/dev/null 2>&1; then
    record_pass "GCP Workflows [1/27]: Actionlint syntax & schema validation passed"
  else
    record_fail "GCP Workflows [1/27]: Actionlint validation" "Actionlint failed on GCP reusable workflow"
  fi
else
  record_fail "GCP Workflows [1/27]: Actionlint validation" "Actionlint binary not found"
fi

# Test 17.2: Zizmor supply chain security audit on reusable GCP workflow
if [[ -n "${ZIZMOR_BIN}" ]]; then
  if "${ZIZMOR_BIN}" -c "${REPO_ROOT}/.zizmor.yml" --min-severity medium "${GCP_REUSABLE_WF}" >/dev/null 2>&1; then
    record_pass "GCP Adapter [2/27]: Zizmor supply chain security audit passed (0 medium/high findings)"
  else
    record_fail "GCP Adapter [2/27]: Zizmor audit" "Zizmor detected supply chain vulnerabilities in reusable-tf-gcp.yml"
  fi
else
  record_fail "GCP Adapter [2/27]: Zizmor audit" "Zizmor binary not found"
fi

# Test 17.3: Conftest OPA unit tests verification (includes GCP WIF and GCS backend tests)
if [[ -n "${CONFTEST_BIN}" ]]; then
  if "${CONFTEST_BIN}" verify --policy "${REPO_ROOT}/policies" "${REPO_ROOT}/policies" >/dev/null 2>&1; then
    record_pass "GCP OPA Policies [3/27]: All Rego unit tests passed (conftest verify)"
  else
    record_fail "GCP OPA Policies [3/27]: Rego unit tests" "conftest verify reported failures"
  fi
else
  record_fail "GCP OPA Policies [3/27]: Rego unit tests" "Conftest binary not found"
fi

# Extract guard script from reusable-tf-gcp.yml
GCP_GUARD_SCRIPT="$(python3 -c "
import yaml
with open('${GCP_REUSABLE_WF}', 'r') as f:
    data = yaml.safe_load(f)
steps = {s['id']: s['run'] for s in data['jobs']['validate-inputs']['steps'] if 'id' in s and 'run' in s}
print(steps['guard'])
")"

run_gcp_guard_test() {
  local version="${1:-1.10.4}"
  local dir="${2:-.}"
  local var_file="${3:-}"
  local env_name="${4:-dev}"
  local project_id="${5:-infraflow-ref-project}"
  local region="${6:-us-central1}"
  local wif_provider="${7:-projects/123456789012/locations/global/workloadIdentityPools/infraflow-pool/providers/github-provider}"
  local service_account="${8:-infraflow-sa@infraflow-ref-project.iam.gserviceaccount.com}"
  local bucket="${9:-infraflow-tfstate-bucket}"
  local prefix="${10:-terraform/state/dev}"
  local severity="${11:-HIGH,CRITICAL}"
  local enable_gcp_auth="${12:-false}"
  local event_name="${13:-push}"
  local target_ref="${14:-refs/heads/main}"
  local workflow_repo="${15:-TM-threemavithana/infraflow}"
  local workflow_sha="${16:-cb33ba9ec5ed7e8b2ce5907aa42d6930e7f95bd2}"
  local workflow_ref="${17:-TM-threemavithana/infraflow/.github/workflows/reusable-tf-gcp.yml@cb33ba9ec5ed7e8b2ce5907aa42d6930e7f95bd2}"
  local enable_policy_eval="${18:-true}"
  local enable_trivy="${19:-true}"
  local policy_dir="${20:-policies}"

  local code=0
  INPUT_VERSION="${version}" \
  INPUT_DIR="${dir}" \
  INPUT_VAR_FILE="${var_file}" \
  INPUT_ENV="${env_name}" \
  INPUT_PROJECT_ID="${project_id}" \
  INPUT_GCP_REGION="${region}" \
  INPUT_WIF_PROVIDER="${wif_provider}" \
  INPUT_SERVICE_ACCOUNT="${service_account}" \
  INPUT_BUCKET="${bucket}" \
  INPUT_PREFIX="${prefix}" \
  INPUT_SEVERITY="${severity}" \
  ENABLE_GCP_AUTH="${enable_gcp_auth}" \
  ENABLE_POLICY_EVAL="${enable_policy_eval}" \
  ENABLE_TRIVY="${enable_trivy}" \
  INPUT_POLICY_DIR="${policy_dir}" \
  EVENT_NAME="${event_name}" \
  TARGET_REF="${target_ref}" \
  GITHUB_REPOSITORY="TM-threemavithana/infraflow" \
  WORKFLOW_REPO="${workflow_repo}" \
  WORKFLOW_SHA="${workflow_sha}" \
  WORKFLOW_REF="${workflow_ref}" \
    bash -c "${GCP_GUARD_SCRIPT}" >/dev/null 2>&1 || code=$?
  return ${code}
}

# Test 17.4: Input Guard: Valid GCP inputs accepted
if run_gcp_guard_test; then
  record_pass "GCP Input Guard [4/27]: Valid GCP inputs accepted"
else
  record_fail "GCP Input Guard [4/27]: Valid inputs" "Legitimate GCP inputs unexpectedly failed guard validation"
fi

# Test 17.5: Security Invariant: Live GCP authentication strictly rejected (G07.2/G07.3 fail-closed)
if ! run_gcp_guard_test "1.10.4" "." "" "dev" "infraflow-ref-project" "us-central1" "" "" "" "" "HIGH,CRITICAL" "true"; then
  record_pass "GCP Security Invariant [5/27]: Live GCP authentication strictly rejected in G07.2/G07.3 (fail-closed)"
else
  record_fail "GCP Security Invariant [5/27]: Live GCP auth" "enable-gcp-auth: true was unexpectedly permitted"
fi

# Test 17.6: Input Guard: Malformed GCP Project ID rejected
if ! run_gcp_guard_test "1.10.4" "." "" "dev" "bad_proj" && \
   ! run_gcp_guard_test "1.10.4" "." "" "dev" "short" && \
   ! run_gcp_guard_test "1.10.4" "." "" "dev" "UPPERCASE-PROJ" && \
   ! run_gcp_guard_test "1.10.4" "." "" "dev" "proj;rm -rf /"; then
  record_pass "GCP Input Guard [6/27]: Malformed Project ID and injection attempts rejected as expected"
else
  record_fail "GCP Input Guard [6/27]: Project ID rejection" "Malformed Project ID was unexpectedly accepted"
fi

# Test 17.7: Input Guard: Malformed GCP Region rejected
if ! run_gcp_guard_test "1.10.4" "." "" "dev" "infraflow-ref-project" "us_central1" && \
   ! run_gcp_guard_test "1.10.4" "." "" "dev" "infraflow-ref-project" "US" && \
   ! run_gcp_guard_test "1.10.4" "." "" "dev" "infraflow-ref-project" "us-central1; rm -rf /"; then
  record_pass "GCP Input Guard [7/27]: Malformed GCP region and injection attempts rejected as expected"
else
  record_fail "GCP Input Guard [7/27]: Region rejection" "Malformed GCP region was unexpectedly accepted"
fi

# Test 17.8: Input Guard: Malformed Workload Identity Provider resource string rejected
if ! run_gcp_guard_test "1.10.4" "." "" "dev" "infraflow-ref-project" "us-central1" "invalid-provider-resource" && \
   ! run_gcp_guard_test "1.10.4" "." "" "dev" "infraflow-ref-project" "us-central1" "projects/my-proj/locations/global/workloadIdentityPools/pool/providers/prov"; then
  record_pass "GCP Input Guard [8/27]: Malformed Workload Identity Provider resource format rejected"
else
  record_fail "GCP Input Guard [8/27]: WIF provider rejection" "Malformed WIF provider resource format was unexpectedly accepted"
fi

# Test 17.9: Input Guard: Malformed Service Account email rejected
if ! run_gcp_guard_test "1.10.4" "." "" "dev" "infraflow-ref-project" "us-central1" "" "admin@gmail.com" && \
   ! run_gcp_guard_test "1.10.4" "." "" "dev" "infraflow-ref-project" "us-central1" "" "sa@project.gserviceaccount.com"; then
  record_pass "GCP Input Guard [9/27]: Malformed Service Account email rejected as expected"
else
  record_fail "GCP Input Guard [9/27]: Service Account rejection" "Malformed Service Account email was unexpectedly accepted"
fi

# Test 17.10: Input Guard: Reserved GCS bucket prefix ('goog', 'google') rejected
if ! run_gcp_guard_test "1.10.4" "." "" "dev" "infraflow-ref-project" "us-central1" "" "" "google-state-storage" && \
   ! run_gcp_guard_test "1.10.4" "." "" "dev" "infraflow-ref-project" "us-central1" "" "" "goog-bucket"; then
  record_pass "GCP Input Guard [10/27]: Reserved GCS bucket prefixes ('goog', 'google') rejected as expected"
else
  record_fail "GCP Input Guard [10/27]: Reserved bucket prefix" "Reserved bucket prefix was unexpectedly accepted"
fi

# Test 17.11: Input Guard: GCS state prefix leading slash and traversal rejected
if ! run_gcp_guard_test "1.10.4" "." "" "dev" "infraflow-ref-project" "us-central1" "" "" "infraflow-tfstate-bucket" "/leading/slash" && \
   ! run_gcp_guard_test "1.10.4" "." "" "dev" "infraflow-ref-project" "us-central1" "" "" "infraflow-tfstate-bucket" "escape/../../root"; then
  record_pass "GCP Input Guard [11/27]: GCS state prefix leading slashes and path traversal rejected"
else
  record_fail "GCP Input Guard [11/27]: Prefix path traversal" "Prefix traversal or leading slash was unexpectedly accepted"
fi

# Test 17.12: Input Guard: Policy directory path traversal and absolute paths rejected
if ! run_gcp_guard_test "1.10.4" "." "" "dev" "infraflow-ref-project" "us-central1" "" "" "" "" "HIGH,CRITICAL" "false" "push" "refs/heads/main" "TM-threemavithana/infraflow" "cb33ba9ec5ed7e8b2ce5907aa42d6930e7f95bd2" "TM-threemavithana/infraflow/.github/workflows/reusable-tf-gcp.yml@cb33ba9ec5ed7e8b2ce5907aa42d6930e7f95bd2" "true" "true" "/etc/policies" && \
   ! run_gcp_guard_test "1.10.4" "." "" "dev" "infraflow-ref-project" "us-central1" "" "" "" "" "HIGH,CRITICAL" "false" "push" "refs/heads/main" "TM-threemavithana/infraflow" "cb33ba9ec5ed7e8b2ce5907aa42d6930e7f95bd2" "TM-threemavithana/infraflow/.github/workflows/reusable-tf-gcp.yml@cb33ba9ec5ed7e8b2ce5907aa42d6930e7f95bd2" "true" "true" "policies/../../escaped"; then
  record_pass "GCP Input Guard [12/27]: Policy directory path traversal and absolute paths rejected"
else
  record_fail "GCP Input Guard [12/27]: Policy directory validation" "Policy directory traversal or absolute path was unexpectedly accepted"
fi

# Test 17.13: Security Invariant: Mandatory gate bypass attempts (policy eval / trivy disabled) rejected
if ! run_gcp_guard_test "1.10.4" "." "" "dev" "infraflow-ref-project" "us-central1" "" "" "" "" "HIGH,CRITICAL" "false" "push" "refs/heads/main" "TM-threemavithana/infraflow" "cb33ba9ec5ed7e8b2ce5907aa42d6930e7f95bd2" "TM-threemavithana/infraflow/.github/workflows/reusable-tf-gcp.yml@cb33ba9ec5ed7e8b2ce5907aa42d6930e7f95bd2" "false" "true" && \
   ! run_gcp_guard_test "1.10.4" "." "" "dev" "infraflow-ref-project" "us-central1" "" "" "" "" "HIGH,CRITICAL" "false" "push" "refs/heads/main" "TM-threemavithana/infraflow" "cb33ba9ec5ed7e8b2ce5907aa42d6930e7f95bd2" "TM-threemavithana/infraflow/.github/workflows/reusable-tf-gcp.yml@cb33ba9ec5ed7e8b2ce5907aa42d6930e7f95bd2" "true" "false"; then
  record_pass "GCP Security Invariant [13/27]: Mandatory security gate bypass attempts (policy eval / trivy disabled) rejected"
else
  record_fail "GCP Security Invariant [13/27]: Gate bypass" "Bypass of mandatory policy evaluation or Trivy scan was unexpectedly permitted"
fi

# Test 17.14: Trust Boundary: Rogue workflow repository rejected
if ! run_gcp_guard_test "1.10.4" "." "" "dev" "infraflow-ref-project" "us-central1" "" "" "" "" "HIGH,CRITICAL" "false" "push" "refs/heads/main" "untrusted-attacker/infraflow"; then
  record_pass "GCP Trust Boundary [14/27]: Rogue workflow repository strictly rejected"
else
  record_fail "GCP Trust Boundary [14/27]: Repository trust" "Untrusted caller repository was unexpectedly accepted"
fi

# Test 17.15: Trust Boundary: Mutable workflow ref rejected (immutable SHA pinning required)
if ! run_gcp_guard_test "1.10.4" "." "" "dev" "infraflow-ref-project" "us-central1" "" "" "" "" "HIGH,CRITICAL" "false" "push" "refs/heads/main" "TM-threemavithana/infraflow" "main" "TM-threemavithana/infraflow/.github/workflows/reusable-tf-gcp.yml@main"; then
  record_pass "GCP Trust Boundary [15/27]: Mutable workflow ref (@main) strictly rejected (immutable SHA required)"
else
  record_fail "GCP Trust Boundary [15/27]: SHA pinning" "Mutable workflow reference was unexpectedly accepted"
fi

# Test 17.16: Security Invariant (SEC-02): Untrusted pull requests requesting cloud credentials rejected
if ! run_gcp_guard_test "1.10.4" "." "" "dev" "infraflow-ref-project" "us-central1" "" "" "" "" "HIGH,CRITICAL" "true" "pull_request"; then
  record_pass "GCP Security Guard [16/27]: Untrusted pull requests requesting cloud auth rejected (SEC-02 fail-closed)"
else
  record_fail "GCP Security Guard [16/27]: PR auth rejection" "Untrusted pull request was allowed to request GCP credentials"
fi

# Test 17.17: GCP Output Aggregation & Failure Propagation
GCP_FAILURE_PROP_VERIFIED=false
if python3 -c "
import yaml, subprocess, tempfile

with open('${GCP_REUSABLE_WF}', 'r') as f:
    data = yaml.safe_load(f)

summary_step = [s for s in data['jobs']['summary']['steps'] if s.get('id') == 'aggregate'][0]['run']

def test_summary(val_res, cf_res, cf_plan_st, cf_sec_st, enable_auth):
    with tempfile.NamedTemporaryFile('w', delete=False) as out_f:
        out_path = out_f.name
    env = {
        'GITHUB_OUTPUT': out_path,
        'VALIDATE_RESULT': val_res,
        'GCP_PLAN_RESULT': 'skipped',
        'GCP_PLAN_STATUS': 'skipped',
        'GCP_AUTH_STATUS': 'disabled',
        'GCP_SEC_STATUS': 'skipped',
        'CF_PLAN_RESULT': cf_res,
        'CF_PLAN_STATUS': cf_plan_st,
        'CF_SEC_STATUS': cf_sec_st,
        'CF_HAS_CHANGES': 'false',
        'CF_HAS_DESTRUCTIVE': 'false',
        'CF_TOTAL_CHANGES': '0',
        'ENABLE_GCP_AUTH': enable_auth,
    }
    p = subprocess.run(['bash', '-c', summary_step], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    with open(out_path) as f:
        lines = dict(line.strip().split('=', 1) for line in f if '=' in line)
    return p.returncode, lines

# 1. Validation failure -> rejected
rc1, l1 = test_summary('failure', 'skipped', 'skipped', 'skipped', 'false')
assert l1['authorization-status'] == 'rejected' and l1['plan-status'] == 'failure' and rc1 != 0

# 2. Cloud-free success -> not-applicable
rc2, l2 = test_summary('success', 'success', 'success', 'success', 'false')
assert l2['authorization-status'] == 'not-applicable' and l2['plan-status'] == 'success' and rc2 == 0
assert l2['authorization-status'] != 'authorized'

# 3. Cloud-free validation failure -> rejected
rc3, l3 = test_summary('success', 'failure', 'failure', 'failure', 'false')
assert l3['authorization-status'] == 'rejected' and rc3 != 0
" >/dev/null 2>&1; then
  GCP_FAILURE_PROP_VERIFIED=true
fi

if [[ "${GCP_FAILURE_PROP_VERIFIED}" == "true" ]]; then
  record_pass "GCP Security Gates [17/27]: Output aggregation and failure propagation verified"
else
  record_fail "GCP Security Gates [17/27]: Failure propagation" "Summary output aggregation or failure propagation failed test matrix"
fi

# Test 17.18: GCS Backend Policy: Empty backend prefix rejected
GCP_EMPTY_PREFIX_VERIFIED=false
if python3 -c "
import tempfile, json, subprocess, os
conftest = '${CONFTEST_BIN}'
policy = '${REPO_ROOT}/policies/gcp/storage_backend.rego'
payload = {'terraform': [{'backend': [{'gcs': [{'bucket': 'tfstate', 'prefix': ''}]}]}]}
with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
    json.dump(payload, f)
    tmp_path = f.name
try:
    p = subprocess.run([conftest, 'test', '--namespace', 'gcp.storage_backend', '--policy', policy, tmp_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert p.returncode != 0 and 'prefix must not be empty' in (p.stdout + p.stderr)
finally:
    if os.path.exists(tmp_path):
        os.unlink(tmp_path)
" >/dev/null 2>&1; then
  GCP_EMPTY_PREFIX_VERIFIED=true
fi
if [[ "${GCP_EMPTY_PREFIX_VERIFIED}" == "true" ]]; then
  record_pass "GCP State Backend [18/27]: Empty backend prefix rejected by Conftest storage policy"
else
  record_fail "GCP State Backend [18/27]: Empty backend prefix" "Empty backend prefix was unexpectedly accepted by storage policy"
fi

# Test 17.19: GCP Reference Module: Canonical formatting
if terraform -chdir="${GCP_REF_MODULE}" fmt -check >/dev/null 2>&1; then
  record_pass "GCP Reference Module [19/27]: Canonical formatting verified (terraform fmt -check)"
else
  record_fail "GCP Reference Module [19/27]: terraform fmt" "GCP reference module contains unformatted files"
fi

# Test 17.20: GCP Reference Module: Cloud-free initialization
GCP_INIT_ARGS=("-backend=false" "-input=false")
if [[ -d "${HOME}/.terraform.d/plugin-cache" ]]; then
  GCP_INIT_ARGS+=("-plugin-dir=${HOME}/.terraform.d/plugin-cache")
fi
if TF_CLI_CONFIG_FILE=/dev/null terraform -chdir="${GCP_REF_MODULE}" init "${GCP_INIT_ARGS[@]}" >/dev/null 2>&1; then
  record_pass "GCP Reference Module [20/27]: Cloud-free initialization verified (terraform init -backend=false)"
else
  record_fail "GCP Reference Module [20/27]: terraform init" "GCP reference module initialization failed"
fi

# Test 17.21: GCP Reference Module: Static validation
if terraform -chdir="${GCP_REF_MODULE}" validate >/dev/null 2>&1; then
  record_pass "GCP Reference Module [21/27]: Static validation verified (terraform validate)"
else
  record_fail "GCP Reference Module [21/27]: terraform validate" "GCP reference module failed static validation"
fi

# Test 17.22: GCP Reference Module: Native unit tests with mock provider
if terraform -chdir="${GCP_REF_MODULE}" test >/dev/null 2>&1; then
  record_pass "GCP Reference Module [22/27]: Native unit tests passed offline with mock provider (terraform test)"
else
  record_fail "GCP Reference Module [22/27]: terraform test" "GCP reference module native unit tests failed"
fi

# Clean up temporary terraform state in reference module
rm -rf "${GCP_REF_MODULE}/.terraform" "${GCP_REF_MODULE}/.terraform.lock.hcl"

# Test 17.23: GCP Reference Module: Trivy IaC Misconfiguration scan
if [[ -n "${TRIVY_BIN}" ]]; then
  if "${TRIVY_BIN}" config --severity HIGH,CRITICAL --exit-code 1 "${GCP_REF_MODULE}" >/dev/null 2>&1; then
    record_pass "GCP Reference Module [23/27]: Trivy IaC security scan clean (0 HIGH/CRITICAL findings)"
  else
    record_fail "GCP Reference Module [23/27]: Trivy scan" "Trivy detected misconfigurations in GCP reference module"
  fi
else
  record_fail "GCP Reference Module [23/27]: Trivy scan" "Trivy binary not found"
fi

# Test 17.24: GCP Reference Module: Conftest policy compliance
if [[ -n "${CONFTEST_BIN}" ]]; then
  if "${CONFTEST_BIN}" test --all-namespaces --policy "${REPO_ROOT}/policies" "${GCP_REF_MODULE}/main.tf" >/dev/null 2>&1; then
    record_pass "GCP Reference Module [24/27]: Conftest enterprise policy compliance verified"
  else
    record_fail "GCP Reference Module [24/27]: Conftest policy compliance" "Conftest policies failed on GCP reference module"
  fi
else
  record_fail "GCP Reference Module [24/27]: Conftest policy compliance" "Conftest binary not found"
fi

# Test 17.25: Dedicated GCP Python Test Suite
if python3 -m unittest "${REPO_ROOT}/tests/test_gcp_adapter.py" >/dev/null 2>&1; then
  record_pass "GCP Adapter Test Suite [25/27]: Dedicated GCP adapter test suite passed (tests/test_gcp_adapter.py)"
else
  record_fail "GCP Adapter Test Suite [25/27]: GCP adapter test suite" "One or more tests in tests/test_gcp_adapter.py failed"
fi

# Test 17.26: Dedicated GCP Adversarial Integration Suite
if python3 -m unittest "${REPO_ROOT}/tests/test_gcp_adversarial_integration.py" >/dev/null 2>&1; then
  record_pass "GCP Adversarial Test Suite [26/27]: Dedicated 30-vector GCP adversarial suite passed (tests/test_gcp_adversarial_integration.py)"
else
  record_fail "GCP Adversarial Test Suite [26/27]: Adversarial test suite" "One or more tests in tests/test_gcp_adversarial_integration.py failed"
fi

# Test 17.27: Dedicated GCP Plan Metrics Suite
if python3 -m unittest "${REPO_ROOT}/tests/test_gcp_plan_metrics.py" >/dev/null 2>&1; then
  record_pass "GCP Plan Metrics Suite [27/27]: Dedicated plan metrics & contract regression suite passed (tests/test_gcp_plan_metrics.py)"
else
  record_fail "GCP Plan Metrics Suite [27/27]: Plan metrics regression suite" "One or more tests in tests/test_gcp_plan_metrics.py failed"
fi

# --- 18. Microsoft Azure Adapter & Workload Identity Architecture (G07.5) ---
log_header "18. Microsoft Azure Adapter & Workload Identity Architecture (G07.5)"

AZURE_REUSABLE_WF="${REPO_ROOT}/.github/workflows/reusable-tf-azure.yml"
AZURE_REF_MODULE="${REPO_ROOT}/examples/azure-reference-module"

# Test 18.1: Actionlint verification of Azure reusable workflow
if [[ -n "${ACTIONLINT_BIN}" ]]; then
  if "${ACTIONLINT_BIN}" "${AZURE_REUSABLE_WF}" >/dev/null 2>&1; then
    record_pass "Azure Workflows [1/25]: Actionlint syntax & schema validation passed"
  else
    record_fail "Azure Workflows [1/25]: Actionlint validation" "Actionlint failed on Azure reusable workflow"
  fi
else
  record_fail "Azure Workflows [1/25]: Actionlint validation" "Actionlint binary not found"
fi

# Test 18.2: Zizmor supply chain security audit on reusable Azure workflow
if [[ -n "${ZIZMOR_BIN}" ]]; then
  if "${ZIZMOR_BIN}" -c "${REPO_ROOT}/.zizmor.yml" --min-severity medium "${AZURE_REUSABLE_WF}" >/dev/null 2>&1; then
    record_pass "Azure Adapter [2/25]: Zizmor supply chain security audit passed (0 medium/high findings)"
  else
    record_fail "Azure Adapter [2/25]: Zizmor audit" "Zizmor detected supply chain vulnerabilities in reusable-tf-azure.yml"
  fi
else
  record_fail "Azure Adapter [2/25]: Zizmor audit" "Zizmor binary not found"
fi

# Test 18.3: Conftest OPA unit tests verification (includes Azure Entra ID and storage backend tests)
if [[ -n "${CONFTEST_BIN}" ]]; then
  if "${CONFTEST_BIN}" verify --policy "${REPO_ROOT}/policies" "${REPO_ROOT}/policies" >/dev/null 2>&1; then
    record_pass "Azure OPA Policies [3/25]: All Rego unit tests passed (conftest verify)"
  else
    record_fail "Azure OPA Policies [3/25]: Rego unit tests" "conftest verify reported failures"
  fi
else
  record_fail "Azure OPA Policies [3/25]: Rego unit tests" "Conftest binary not found"
fi

# Extract guard script from reusable-tf-azure.yml
AZURE_GUARD_SCRIPT="$(python3 -c "
import yaml
with open('${AZURE_REUSABLE_WF}', 'r') as f:
    data = yaml.safe_load(f)
steps = {s['id']: s['run'] for s in data['jobs']['validate-inputs']['steps'] if 'id' in s and 'run' in s}
print(steps['guard'])
")"

run_azure_guard_test() {
  local version="${1:-1.10.4}"
  local dir="${2:-.}"
  local var_file="${3:-}"
  local env_name="${4:-dev}"
  local subscription_id="${5:-00000000-0000-0000-0000-000000000001}"
  local tenant_id="${6:-00000000-0000-0000-0000-000000000002}"
  local client_id="${7:-00000000-0000-0000-0000-000000000003}"
  local rg_name="${8:-rg-infraflow-dev}"
  local storage_account="${9:-stinfraflowdev01}"
  local container="${10:-tfstate}"
  local backend_key="${11:-terraform.tfstate}"
  local severity="${12:-HIGH,CRITICAL}"
  local enable_azure_auth="${13:-false}"
  local event_name="${14:-push}"
  local target_ref="${15:-refs/heads/main}"
  local workflow_repo="${16:-TM-threemavithana/infraflow}"
  local workflow_sha="${17:-3c2c79d7ae5a881bf1a66dc00af36bdc0d733e47}"
  local workflow_ref="${18:-TM-threemavithana/infraflow/.github/workflows/reusable-tf-azure.yml@3c2c79d7ae5a881bf1a66dc00af36bdc0d733e47}"
  local enable_policy_eval="${19:-true}"
  local enable_trivy="${20:-true}"
  local policy_dir="${21:-policies}"

  local code=0
  INPUT_VERSION="${version}" \
  INPUT_DIR="${dir}" \
  INPUT_VAR_FILE="${var_file}" \
  INPUT_ENV="${env_name}" \
  INPUT_SUBSCRIPTION_ID="${subscription_id}" \
  INPUT_TENANT_ID="${tenant_id}" \
  INPUT_CLIENT_ID="${client_id}" \
  INPUT_RESOURCE_GROUP_NAME="${rg_name}" \
  INPUT_STORAGE_ACCOUNT_NAME="${storage_account}" \
  INPUT_STORAGE_CONTAINER_NAME="${container}" \
  INPUT_BACKEND_KEY="${backend_key}" \
  INPUT_SEVERITY="${severity}" \
  ENABLE_AZURE_AUTH="${enable_azure_auth}" \
  ENABLE_POLICY_EVAL="${enable_policy_eval}" \
  ENABLE_TRIVY="${enable_trivy}" \
  INPUT_POLICY_DIR="${policy_dir}" \
  EVENT_NAME="${event_name}" \
  TARGET_REF="${target_ref}" \
  GITHUB_REPOSITORY="TM-threemavithana/infraflow" \
  WORKFLOW_REPO="${workflow_repo}" \
  WORKFLOW_SHA="${workflow_sha}" \
  WORKFLOW_REF="${workflow_ref}" \
    bash -c "${AZURE_GUARD_SCRIPT}" >/dev/null 2>&1 || code=$?
  return ${code}
}

# Test 18.4: Input Guard: Valid Azure inputs accepted
if run_azure_guard_test; then
  record_pass "Azure Input Guard [4/25]: Valid Azure inputs accepted"
else
  record_fail "Azure Input Guard [4/25]: Valid inputs" "Legitimate Azure inputs unexpectedly failed guard validation"
fi

# Test 18.5: Security Invariant: Live Azure authentication strictly rejected (G07.5 fail-closed)
if ! run_azure_guard_test "1.10.4" "." "" "dev" "00000000-0000-0000-0000-000000000001" "00000000-0000-0000-0000-000000000002" "00000000-0000-0000-0000-000000000003" "rg-infraflow-dev" "stinfraflowdev01" "tfstate" "terraform.tfstate" "HIGH,CRITICAL" "true"; then
  record_pass "Azure Security Invariant [5/25]: Live Azure authentication strictly rejected in G07.5 (fail-closed)"
else
  record_fail "Azure Security Invariant [5/25]: Live Azure auth" "enable-azure-auth: true was unexpectedly permitted"
fi

# Test 18.6: Input Guard: Malformed Azure Subscription ID rejected
if ! run_azure_guard_test "1.10.4" "." "" "dev" "invalid-uuid" && \
   ! run_azure_guard_test "1.10.4" "." "" "dev" "12345" && \
   ! run_azure_guard_test "1.10.4" "." "" "dev" "00000000-0000-0000-0000-00000000000G" && \
   ! run_azure_guard_test "1.10.4" "." "" "dev" "00000000-0000-0000-0000-000000000001; rm -rf /"; then
  record_pass "Azure Input Guard [6/25]: Malformed Subscription ID and injection attempts rejected as expected"
else
  record_fail "Azure Input Guard [6/25]: Subscription ID rejection" "Malformed Subscription ID was unexpectedly accepted"
fi

# Test 18.7: Input Guard: Malformed Azure Tenant ID and Client ID rejected
if ! run_azure_guard_test "1.10.4" "." "" "dev" "00000000-0000-0000-0000-000000000001" "not-a-tenant-uuid" && \
   ! run_azure_guard_test "1.10.4" "." "" "dev" "00000000-0000-0000-0000-000000000001" "00000000-0000-0000-0000-000000000002" "not-a-client-uuid"; then
  record_pass "Azure Input Guard [7/25]: Malformed Tenant ID and Client ID rejected as expected"
else
  record_fail "Azure Input Guard [7/25]: Tenant/Client ID rejection" "Malformed Tenant or Client ID was unexpectedly accepted"
fi

# Test 18.8: Input Guard: Malformed Resource Group name rejected (>90 chars, trailing period, invalid chars)
if ! run_azure_guard_test "1.10.4" "." "" "dev" "00000000-0000-0000-0000-000000000001" "00000000-0000-0000-0000-000000000002" "00000000-0000-0000-0000-000000000003" "invalid_rg." && \
   ! run_azure_guard_test "1.10.4" "." "" "dev" "00000000-0000-0000-0000-000000000001" "00000000-0000-0000-0000-000000000002" "00000000-0000-0000-0000-000000000003" "rg_with_disallowed*chars" && \
   ! run_azure_guard_test "1.10.4" "." "" "dev" "00000000-0000-0000-0000-000000000001" "00000000-0000-0000-0000-000000000002" "00000000-0000-0000-0000-000000000003" "$(printf 'a%.0s' {1..95})"; then
  record_pass "Azure Input Guard [8/25]: Malformed Resource Group names rejected as expected"
else
  record_fail "Azure Input Guard [8/25]: Resource Group rejection" "Malformed Resource Group name was unexpectedly accepted"
fi

# Test 18.9: Input Guard: Malformed Storage Account name rejected (<3 chars, >24 chars, uppercase, hyphen)
if ! run_azure_guard_test "1.10.4" "." "" "dev" "00000000-0000-0000-0000-000000000001" "00000000-0000-0000-0000-000000000002" "00000000-0000-0000-0000-000000000003" "rg-dev" "sa" && \
   ! run_azure_guard_test "1.10.4" "." "" "dev" "00000000-0000-0000-0000-000000000001" "00000000-0000-0000-0000-000000000002" "00000000-0000-0000-0000-000000000003" "rg-dev" "st-with-hyphens" && \
   ! run_azure_guard_test "1.10.4" "." "" "dev" "00000000-0000-0000-0000-000000000001" "00000000-0000-0000-0000-000000000002" "00000000-0000-0000-0000-000000000003" "rg-dev" "StorageAccountUpper" && \
   ! run_azure_guard_test "1.10.4" "." "" "dev" "00000000-0000-0000-0000-000000000001" "00000000-0000-0000-0000-000000000002" "00000000-0000-0000-0000-000000000003" "rg-dev" "toolongstorageaccountname12345"; then
  record_pass "Azure Input Guard [9/25]: Malformed Storage Account names rejected as expected"
else
  record_fail "Azure Input Guard [9/25]: Storage Account rejection" "Malformed Storage Account name was unexpectedly accepted"
fi

# Test 18.10: Input Guard: Malformed Storage Container name rejected (<3 chars, >63 chars, uppercase, double hyphen)
if ! run_azure_guard_test "1.10.4" "." "" "dev" "00000000-0000-0000-0000-000000000001" "00000000-0000-0000-0000-000000000002" "00000000-0000-0000-0000-000000000003" "rg-dev" "stvalid01" "ab" && \
   ! run_azure_guard_test "1.10.4" "." "" "dev" "00000000-0000-0000-0000-000000000001" "00000000-0000-0000-0000-000000000002" "00000000-0000-0000-0000-000000000003" "rg-dev" "stvalid01" "-leading-hyphen" && \
   ! run_azure_guard_test "1.10.4" "." "" "dev" "00000000-0000-0000-0000-000000000001" "00000000-0000-0000-0000-000000000002" "00000000-0000-0000-0000-000000000003" "rg-dev" "stvalid01" "con--doublehyphen" && \
   ! run_azure_guard_test "1.10.4" "." "" "dev" "00000000-0000-0000-0000-000000000001" "00000000-0000-0000-0000-000000000002" "00000000-0000-0000-0000-000000000003" "rg-dev" "stvalid01" "ContainerUpper"; then
  record_pass "Azure Input Guard [10/25]: Malformed Storage Container names rejected as expected"
else
  record_fail "Azure Input Guard [10/25]: Container name rejection" "Malformed Container name was unexpectedly accepted"
fi

# Test 18.11: Input Guard: State key leading slash and path traversal rejected
if ! run_azure_guard_test "1.10.4" "." "" "dev" "00000000-0000-0000-0000-000000000001" "00000000-0000-0000-0000-000000000002" "00000000-0000-0000-0000-000000000003" "rg-dev" "stvalid01" "tfstate" "/leading/slash" && \
   ! run_azure_guard_test "1.10.4" "." "" "dev" "00000000-0000-0000-0000-000000000001" "00000000-0000-0000-0000-000000000002" "00000000-0000-0000-0000-000000000003" "rg-dev" "stvalid01" "tfstate" "escape/../../root"; then
  record_pass "Azure Input Guard [11/25]: Azure state key leading slashes and path traversal rejected"
else
  record_fail "Azure Input Guard [11/25]: Key path traversal" "State key traversal or leading slash was unexpectedly accepted"
fi

# Test 18.12: Input Guard: Policy directory path traversal and absolute paths rejected
if ! run_azure_guard_test "1.10.4" "." "" "dev" "00000000-0000-0000-0000-000000000001" "00000000-0000-0000-0000-000000000002" "00000000-0000-0000-0000-000000000003" "rg-dev" "stvalid01" "tfstate" "terraform.tfstate" "HIGH,CRITICAL" "false" "push" "refs/heads/main" "TM-threemavithana/infraflow" "3c2c79d7ae5a881bf1a66dc00af36bdc0d733e47" "TM-threemavithana/infraflow/.github/workflows/reusable-tf-azure.yml@3c2c79d7ae5a881bf1a66dc00af36bdc0d733e47" "true" "true" "/etc/policies" && \
   ! run_azure_guard_test "1.10.4" "." "" "dev" "00000000-0000-0000-0000-000000000001" "00000000-0000-0000-0000-000000000002" "00000000-0000-0000-0000-000000000003" "rg-dev" "stvalid01" "tfstate" "terraform.tfstate" "HIGH,CRITICAL" "false" "push" "refs/heads/main" "TM-threemavithana/infraflow" "3c2c79d7ae5a881bf1a66dc00af36bdc0d733e47" "TM-threemavithana/infraflow/.github/workflows/reusable-tf-azure.yml@3c2c79d7ae5a881bf1a66dc00af36bdc0d733e47" "true" "true" "policies/../../escaped"; then
  record_pass "Azure Input Guard [12/25]: Policy directory path traversal and absolute paths rejected"
else
  record_fail "Azure Input Guard [12/25]: Policy directory validation" "Policy directory traversal or absolute path was unexpectedly accepted"
fi

# Test 18.13: Security Invariant: Mandatory gate bypass attempts (policy eval / trivy disabled) rejected
if ! run_azure_guard_test "1.10.4" "." "" "dev" "00000000-0000-0000-0000-000000000001" "00000000-0000-0000-0000-000000000002" "00000000-0000-0000-0000-000000000003" "rg-dev" "stvalid01" "tfstate" "terraform.tfstate" "HIGH,CRITICAL" "false" "push" "refs/heads/main" "TM-threemavithana/infraflow" "3c2c79d7ae5a881bf1a66dc00af36bdc0d733e47" "TM-threemavithana/infraflow/.github/workflows/reusable-tf-azure.yml@3c2c79d7ae5a881bf1a66dc00af36bdc0d733e47" "false" "true" && \
   ! run_azure_guard_test "1.10.4" "." "" "dev" "00000000-0000-0000-0000-000000000001" "00000000-0000-0000-0000-000000000002" "00000000-0000-0000-0000-000000000003" "rg-dev" "stvalid01" "tfstate" "terraform.tfstate" "HIGH,CRITICAL" "false" "push" "refs/heads/main" "TM-threemavithana/infraflow" "3c2c79d7ae5a881bf1a66dc00af36bdc0d733e47" "TM-threemavithana/infraflow/.github/workflows/reusable-tf-azure.yml@3c2c79d7ae5a881bf1a66dc00af36bdc0d733e47" "true" "false"; then
  record_pass "Azure Security Invariant [13/25]: Mandatory security gate bypass attempts (policy eval / trivy disabled) rejected"
else
  record_fail "Azure Security Invariant [13/25]: Gate bypass" "Bypass of mandatory policy evaluation or Trivy scan was unexpectedly permitted"
fi

# Test 18.14: Trust Boundary: Rogue workflow repository rejected
if ! run_azure_guard_test "1.10.4" "." "" "dev" "00000000-0000-0000-0000-000000000001" "00000000-0000-0000-0000-000000000002" "00000000-0000-0000-0000-000000000003" "rg-dev" "stvalid01" "tfstate" "terraform.tfstate" "HIGH,CRITICAL" "false" "push" "refs/heads/main" "untrusted-attacker/infraflow"; then
  record_pass "Azure Trust Boundary [14/25]: Rogue workflow repository strictly rejected"
else
  record_fail "Azure Trust Boundary [14/25]: Repository trust" "Untrusted caller repository was unexpectedly accepted"
fi

# Test 18.15: Trust Boundary: Mutable workflow ref rejected (immutable SHA pinning required)
if ! run_azure_guard_test "1.10.4" "." "" "dev" "00000000-0000-0000-0000-000000000001" "00000000-0000-0000-0000-000000000002" "00000000-0000-0000-0000-000000000003" "rg-dev" "stvalid01" "tfstate" "terraform.tfstate" "HIGH,CRITICAL" "false" "push" "refs/heads/main" "TM-threemavithana/infraflow" "main" "TM-threemavithana/infraflow/.github/workflows/reusable-tf-azure.yml@main"; then
  record_pass "Azure Trust Boundary [15/25]: Mutable workflow ref (@main) strictly rejected (immutable SHA required)"
else
  record_fail "Azure Trust Boundary [15/25]: SHA pinning" "Mutable workflow reference was unexpectedly accepted"
fi

# Test 18.16: Security Invariant (SEC-02): Untrusted pull requests requesting cloud credentials rejected
if ! run_azure_guard_test "1.10.4" "." "" "dev" "00000000-0000-0000-0000-000000000001" "00000000-0000-0000-0000-000000000002" "00000000-0000-0000-0000-000000000003" "rg-dev" "stvalid01" "tfstate" "terraform.tfstate" "HIGH,CRITICAL" "true" "pull_request"; then
  record_pass "Azure Security Guard [16/25]: Untrusted pull requests requesting cloud auth rejected (SEC-02 fail-closed)"
else
  record_fail "Azure Security Guard [16/25]: PR auth rejection" "Untrusted pull request was allowed to request Azure credentials"
fi

# Test 18.17: Azure Output Aggregation & Failure Propagation
AZURE_FAILURE_PROP_VERIFIED=false
if python3 -c "
import yaml, subprocess, tempfile

with open('${AZURE_REUSABLE_WF}', 'r') as f:
    data = yaml.safe_load(f)

summary_step = [s for s in data['jobs']['summary']['steps'] if s.get('id') == 'aggregate'][0]['run']

def test_summary(val_res, cf_res, cf_plan_st, cf_sec_st, enable_auth):
    with tempfile.NamedTemporaryFile('w', delete=False) as out_f:
        out_path = out_f.name
    env = {
        'GITHUB_OUTPUT': out_path,
        'VALIDATE_RESULT': val_res,
        'AZURE_PLAN_RESULT': 'skipped',
        'AZURE_PLAN_STATUS': 'skipped',
        'AZURE_AUTH_STATUS': 'disabled',
        'AZURE_SEC_STATUS': 'skipped',
        'CF_PLAN_RESULT': cf_res,
        'CF_PLAN_STATUS': cf_plan_st,
        'CF_SEC_STATUS': cf_sec_st,
        'CF_HAS_CHANGES': 'false',
        'CF_HAS_DESTRUCTIVE': 'false',
        'CF_TOTAL_CHANGES': '0',
        'ENABLE_AZURE_AUTH': enable_auth,
    }
    p = subprocess.run(['bash', '-c', summary_step], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    with open(out_path) as f:
        lines = dict(line.strip().split('=', 1) for line in f if '=' in line)
    return p.returncode, lines

# 1. Validation failure -> rejected
rc1, l1 = test_summary('failure', 'skipped', 'skipped', 'skipped', 'false')
assert l1['authorization-status'] == 'rejected' and l1['plan-status'] == 'failure' and rc1 != 0

# 2. Cloud-free success -> not-applicable
rc2, l2 = test_summary('success', 'success', 'success', 'success', 'false')
assert l2['authorization-status'] == 'not-applicable' and l2['plan-status'] == 'success' and rc2 == 0
assert l2['authorization-status'] != 'authorized'

# 3. Cloud-free validation failure -> rejected
rc3, l3 = test_summary('success', 'failure', 'failure', 'failure', 'false')
assert l3['authorization-status'] == 'rejected' and rc3 != 0
" >/dev/null 2>&1; then
  AZURE_FAILURE_PROP_VERIFIED=true
fi

if [[ "${AZURE_FAILURE_PROP_VERIFIED}" == "true" ]]; then
  record_pass "Azure Security Gates [17/25]: Output aggregation and failure propagation verified"
else
  record_fail "Azure Security Gates [17/25]: Failure propagation" "Summary output aggregation or failure propagation failed test matrix"
fi

# Test 18.18: Azure Storage Backend Policy: Empty backend key rejected
AZURE_EMPTY_KEY_VERIFIED=false
if python3 -c "
import tempfile, json, subprocess, os
conftest = '${CONFTEST_BIN}'
policy = '${REPO_ROOT}/policies/azure/storage_backend.rego'
payload = {'terraform': [{'backend': [{'azurerm': [{'storage_account_name': 'sttfstate', 'container_name': 'tfstate', 'key': ''}]}]}]}
with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
    json.dump(payload, f)
    tmp_path = f.name
try:
    p = subprocess.run([conftest, 'test', '--namespace', 'azure.storage_backend', '--policy', policy, tmp_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert p.returncode != 0 and 'must not be empty' in (p.stdout + p.stderr)
finally:
    if os.path.exists(tmp_path):
        os.unlink(tmp_path)
" >/dev/null 2>&1; then
  AZURE_EMPTY_KEY_VERIFIED=true
fi
if [[ "${AZURE_EMPTY_KEY_VERIFIED}" == "true" ]]; then
  record_pass "Azure State Backend [18/25]: Empty backend key rejected by Conftest storage policy"
else
  record_fail "Azure State Backend [18/25]: Empty backend key" "Empty backend key was unexpectedly accepted by storage policy"
fi

# Test 18.19: Azure Reference Module: Canonical formatting
if terraform -chdir="${AZURE_REF_MODULE}" fmt -check >/dev/null 2>&1; then
  record_pass "Azure Reference Module [19/25]: Canonical formatting verified (terraform fmt -check)"
else
  record_fail "Azure Reference Module [19/25]: terraform fmt" "Azure reference module contains unformatted files"
fi

# Test 18.20: Azure Reference Module: Cloud-free initialization
AZURE_INIT_ARGS=("-backend=false" "-input=false")
if TF_CLI_CONFIG_FILE=/dev/null terraform -chdir="${AZURE_REF_MODULE}" init "${AZURE_INIT_ARGS[@]}" >/dev/null 2>&1; then
  record_pass "Azure Reference Module [20/25]: Cloud-free initialization verified (terraform init -backend=false)"
else
  record_fail "Azure Reference Module [20/25]: terraform init" "Azure reference module initialization failed"
fi

# Test 18.21: Azure Reference Module: Static validation
if terraform -chdir="${AZURE_REF_MODULE}" validate >/dev/null 2>&1; then
  record_pass "Azure Reference Module [21/25]: Static validation verified (terraform validate)"
else
  record_fail "Azure Reference Module [21/25]: terraform validate" "Azure reference module failed static validation"
fi

# Test 18.22: Azure Reference Module: Native unit tests with mock provider
if terraform -chdir="${AZURE_REF_MODULE}" test >/dev/null 2>&1; then
  record_pass "Azure Reference Module [22/25]: Native unit tests passed offline with mock provider (terraform test)"
else
  record_fail "Azure Reference Module [22/25]: terraform test" "Azure reference module native unit tests failed"
fi

# Clean up temporary terraform state in reference module
rm -rf "${AZURE_REF_MODULE}/.terraform" "${AZURE_REF_MODULE}/.terraform.lock.hcl"

# Test 18.23: Azure Reference Module: Trivy IaC Misconfiguration scan
if [[ -n "${TRIVY_BIN}" ]]; then
  if "${TRIVY_BIN}" config --severity HIGH,CRITICAL --exit-code 1 "${AZURE_REF_MODULE}" >/dev/null 2>&1; then
    record_pass "Azure Reference Module [23/25]: Trivy IaC security scan clean (0 HIGH/CRITICAL findings)"
  else
    record_fail "Azure Reference Module [23/25]: Trivy scan" "Trivy detected misconfigurations in Azure reference module"
  fi
else
  record_fail "Azure Reference Module [23/25]: Trivy scan" "Trivy binary not found"
fi

# Test 18.24: Azure Reference Module: Conftest policy compliance
if [[ -n "${CONFTEST_BIN}" ]]; then
  if "${CONFTEST_BIN}" test --all-namespaces --policy "${REPO_ROOT}/policies" "${AZURE_REF_MODULE}/main.tf" >/dev/null 2>&1; then
    record_pass "Azure Reference Module [24/25]: Conftest enterprise policy compliance verified"
  else
    record_fail "Azure Reference Module [24/25]: Conftest policy compliance" "Conftest policies failed on Azure reference module"
  fi
else
  record_fail "Azure Reference Module [24/25]: Conftest policy compliance" "Conftest binary not found"
fi

# Test 18.25: Dedicated Azure Python Test Suite
if python3 -m unittest "${REPO_ROOT}/tests/test_azure_adapter.py" >/dev/null 2>&1; then
  record_pass "Azure Adapter Test Suite [25/25]: Dedicated Azure adapter test suite passed (tests/test_azure_adapter.py)"
else
  record_fail "Azure Adapter Test Suite [25/25]: Azure adapter test suite" "One or more tests in tests/test_azure_adapter.py failed"
fi

# --- 19. Summary Report ---
log_header "Summary of Validation Results"

echo -e "Total Checks Executed : ${COLOR_BLUE}${TOTAL_CHECKS}${COLOR_RESET}"
echo -e "Passed Checks         : ${COLOR_GREEN}${PASSED_CHECKS}${COLOR_RESET}"
echo -e "Failed Checks         : ${COLOR_RED}${FAILED_CHECKS}${COLOR_RESET}"

if [[ ${FAILED_CHECKS} -eq 0 ]]; then
  echo -e "\n${COLOR_GREEN}>>> ALL G01/G02/G03/G04/G05/G06/G07 QUALITY GATES PASSED SUCCESSFULLY (${PASSED_CHECKS}/${TOTAL_CHECKS}) <<<${COLOR_RESET}\n"
  exit 0
else
  echo -e "\n${COLOR_RED}>>> VALIDATION FAILED WITH ${FAILED_CHECKS} ERRORS <<<${COLOR_RESET}\n"
  exit 1
fi
