terraform {
  required_version = ">= 1.6.0"
}

resource "azurerm_storage_account" "insecure_storage" {
  name                            = "insecureblobstorage"
  resource_group_name             = "rg-infraflow"
  location                        = "eastus"
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = true
  min_tls_version                 = "TLS1_0"
}
