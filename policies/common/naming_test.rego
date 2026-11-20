package common.naming_test

import rego.v1
import data.common.naming

test_invalid_resource_name if {
	mock_input := {"resource": {"terraform_data": {"INVALID_UPPERCASE!": [{}]}}}
	res := naming.deny with input as mock_input
	count(res) == 1
}

test_valid_resource_name if {
	mock_input := {"resource": {"terraform_data": {"valid_node-01": [{}]}}}
	res := naming.deny with input as mock_input
	count(res) == 0
}
