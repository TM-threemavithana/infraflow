package aws.network

import rego.v1

sensitive_ports := {22, 3389}

# Rule: Deny unrestricted ingress to sensitive administration ports on aws_security_group
deny contains msg if {
	some name
	sg := input.resource.aws_security_group[name][_]
	ingress := sg.ingress[_]
	some port in sensitive_ports
	ingress.from_port <= port
	ingress.to_port >= port
	ingress.cidr_blocks[_] == "0.0.0.0/0"
	msg := sprintf("Resource 'aws_security_group.%v' permits unrestricted 0.0.0.0/0 ingress to sensitive port %v", [name, port])
}

# Rule: Deny unrestricted ingress on standalone aws_vpc_security_group_ingress_rule
deny contains msg if {
	some name
	rule := input.resource.aws_vpc_security_group_ingress_rule[name][_]
	some port in sensitive_ports
	rule.from_port <= port
	rule.to_port >= port
	rule.cidr_ipv4 == "0.0.0.0/0"
	msg := sprintf("Resource 'aws_vpc_security_group_ingress_rule.%v' permits unrestricted 0.0.0.0/0 ingress to sensitive port %v", [name, port])
}
