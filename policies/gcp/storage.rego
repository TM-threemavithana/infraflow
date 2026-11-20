package gcp.storage

import rego.v1

# Deny GCS bucket unless uniform_bucket_level_access is explicitly true
deny contains msg if {
	some name
	bucket := input.resource.google_storage_bucket[name][_]
	object.get(bucket, "uniform_bucket_level_access", false) != true
	msg := sprintf("Resource 'google_storage_bucket.%v' must explicitly set uniform_bucket_level_access to true", [name])
}
