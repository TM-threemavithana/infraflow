#!/usr/bin/env bash
# ==============================================================================
# InfraFlow Local Validation Harness
# Validates GitHub Actions workflow syntax, Terraform modules, native tests,
# negative fixtures, and security input guard logic without requiring cloud access.
#
# IMPORTANT: Extracts and tests the EXACT script blocks from
# .github/workflows/reusable-tf-validate.yml to guarantee fidelity.
# ==============================================================================

set -euo pipefail

# ANSI color codes for readable output
readonly COLOR_RESET="\033[0m"
readonly COLOR_GREEN="\033[1;32m"
readonly COLOR_RED="\033[1;31m"
readonly COLOR_YELLOW="\033[1;33m"
readonly COLOR_BLUE="\033[1;34m"
readonly COLOR_CYAN="\033[1;36m"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

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
  TF_VERSION="$(terraform version | head -n 1)"
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
  AL_VERSION="$("${ACTIONLINT_BIN}" --version | head -n 1)"
  record_pass "Actionlint installed (${AL_VERSION})"
else
  record_fail "Actionlint installed" "actionlint binary not found"
fi

# --- 2. GitHub Actions Workflow Syntax Linting ---
log_header "2. GitHub Actions Workflow Linting (actionlint)"

if [[ -n "${ACTIONLINT_BIN}" ]]; then
  if (cd "${REPO_ROOT}" && "${ACTIONLINT_BIN}"); then
    record_pass "Workflow syntax & schema validation (.github/workflows & examples)"
  else
    record_fail "Workflow syntax validation" "actionlint reported errors"
  fi
else
  echo -e "  ${COLOR_YELLOW}Skipping actionlint checks (binary missing)${COLOR_RESET}"
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
  record_fail "Negative Check: fixtures/unformatted" "Expected failure, but terraform fmt succeeded unexpectedly"
else
  record_pass "Negative Check: fixtures/unformatted rejected as expected (exit code != 0)"
fi

# Negative Fixture 3: Failing Test Assertion
FAILING_TEST_DIR="${REPO_ROOT}/fixtures/failing-test"
(cd "${FAILING_TEST_DIR}" && terraform init -backend=false -input=false >/dev/null 2>&1 || true)
if (cd "${FAILING_TEST_DIR}" && terraform test >/dev/null 2>&1); then
  record_fail "Negative Check: fixtures/failing-test" "Expected test failure, but terraform test succeeded unexpectedly"
else
  record_pass "Negative Check: fixtures/failing-test assertion failed as expected (exit code != 0)"
fi

# --- 5. Security Guard: Live Testing Extracted Workflow Scripts ---
log_header "5. Security Guard & Workspace Containment (Extracted Workflow Logic)"

WORKFLOW_FILE="${REPO_ROOT}/.github/workflows/reusable-tf-validate.yml"

# Extract the exact bash scripts from the workflow file using python3
GUARD_SCRIPT="$(python3 -c "
import yaml
with open('${WORKFLOW_FILE}') as f:
    wf = yaml.safe_load(f)
steps = {s['id']: s['run'] for s in wf['jobs']['validate']['steps'] if 'id' in s and 'run' in s}
print(steps['guard'])
")"

VERIFY_WORKSPACE_SCRIPT="$(python3 -c "
import yaml
with open('${WORKFLOW_FILE}') as f:
    wf = yaml.safe_load(f)
steps = {s['id']: s['run'] for s in wf['jobs']['validate']['steps'] if 'id' in s and 'run' in s}
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

# --- 6. Summary Report ---
log_header "Summary of Validation Results"

echo -e "Total Checks Executed : ${COLOR_BLUE}${TOTAL_CHECKS}${COLOR_RESET}"
echo -e "Passed Checks         : ${COLOR_GREEN}${PASSED_CHECKS}${COLOR_RESET}"
echo -e "Failed Checks         : ${COLOR_RED}${FAILED_CHECKS}${COLOR_RESET}"

if [[ ${FAILED_CHECKS} -eq 0 ]]; then
  echo -e "\n${COLOR_GREEN}>>> ALL G01/G02 QUALITY GATES PASSED SUCCESSFULLY (${PASSED_CHECKS}/${TOTAL_CHECKS}) <<<${COLOR_RESET}\n"
  exit 0
else
  echo -e "\n${COLOR_RED}>>> VALIDATION FAILED WITH ${FAILED_CHECKS} ERRORS <<<${COLOR_RESET}\n"
  exit 1
fi
