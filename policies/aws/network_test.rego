package aws.network_test

import rego.v1
import data.aws.network

test_unrestricted_ssh_denied if {
	mock_input := {"resource": {"aws_security_group": {"bad_sg": [{
		"ingress": [{
			"from_port": 22,
			"to_port": 22,
			"cidr_blocks": ["0.0.0.0/0"],
		}],
	}]}}}
	res := network.deny with input as mock_input
	count(res) == 1
	contains(res[_], "unrestricted 0.0.0.0/0 ingress to sensitive port 22")
}

test_restricted_ssh_allowed if {
	mock_input := {"resource": {"aws_security_group": {"good_sg": [{
		"ingress": [{
			"from_port": 22,
			"to_port": 22,
			"cidr_blocks": ["10.0.0.0/16"],
		}],
	}]}}}
	res := network.deny with input as mock_input
	count(res) == 0
}

test_unrestricted_http_allowed if {
	mock_input := {"resource": {"aws_security_group": {"web_sg": [{
		"ingress": [{
			"from_port": 80,
			"to_port": 80,
			"cidr_blocks": ["0.0.0.0/0"],
		}],
	}]}}}
	res := network.deny with input as mock_input
	count(res) == 0
}
