terraform {
  required_version = ">= 1.6.0"
}

# 1. Non-cloud resource without tags (legitimately supported)
resource "terraform_data" "compliant_service" {
  input = {
    service = "infraflow-api"
    tier    = "backend"
  }
}

# 2. AWS resource that legitimately does NOT support tags (proves zero false positives)
resource "aws_route_table_association" "compliant_association" {
  subnet_id      = "subnet-0123456789abcdef0"
  route_table_id = "rtb-0123456789abcdef0"
}

# 3. Azure resource that legitimately does NOT support tags (proves zero false positives)
resource "azurerm_subnet_network_security_group_association" "compliant_nsg_assoc" {
  subnet_id                 = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/my-rg/providers/Microsoft.Network/virtualNetworks/my-vnet/subnets/my-subnet"
  network_security_group_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/my-rg/providers/Microsoft.Network/networkSecurityGroups/my-nsg"
}

# 4. GCP resource that legitimately does NOT support labels (proves zero false positives)
resource "google_compute_network" "compliant_vpc" {
  name                    = "infraflow-vpc"
  auto_create_subnetworks = false
}

# 5. AWS taggable resource with fully compliant mandatory tags & private ACL
resource "aws_s3_bucket" "compliant_tagged_bucket" {
  bucket = "infraflow-compliant-prod-storage"
  acl    = "private"

  tags = {
    Environment = "prod"
    ManagedBy   = "terraform"
    Project     = "infraflow"
  }
}

# 6. Azure taggable resource with fully compliant mandatory tags, TLS 1.2, private blob
resource "azurerm_storage_account" "compliant_sa" {
  name                            = "infraflowcompliantsa"
  resource_group_name             = "infraflow-rg"
  location                        = "eastus"
  account_tier                    = "Standard"
  account_replication_type        = "GRS"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false

  tags = {
    Environment = "prod"
    ManagedBy   = "terraform"
    Project     = "infraflow"
  }
}

# 7. GCP labelable resource with fully compliant mandatory labels & uniform access
resource "google_storage_bucket" "compliant_gcs" {
  name                        = "infraflow-compliant-gcs-bucket"
  location                    = "US"
  uniform_bucket_level_access = true

  labels = {
    environment = "prod"
    managed_by  = "terraform"
    project     = "infraflow"
  }
}
