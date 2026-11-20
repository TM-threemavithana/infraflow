package common.naming

import rego.v1

# Resource names must use standard lowercase alphanumeric naming
deny contains msg if {
	some res_type, res_name
	_ := input.resource[res_type][res_name]
	not regex.match("^[a-z0-9_-]+$", res_name)
	msg := sprintf("Resource '%v.%v' name must only contain lowercase alphanumeric characters, dashes, or underscores", [res_type, res_name])
}
