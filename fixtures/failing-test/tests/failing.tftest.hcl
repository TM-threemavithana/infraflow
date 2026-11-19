# Deliberately failing test assertion for negative testing
run "assert_failure" {
  command = plan

  assert {
    condition     = terraform_data.status.input == "INCORRECT_EXPECTATION"
    error_message = "Intentional assertion failure for negative verification testing."
  }
}
