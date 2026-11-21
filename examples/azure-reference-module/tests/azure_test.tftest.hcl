mock_provider "azurerm" {}

variables {
  subscription_id      = "00000000-0000-0000-0000-000000000000"
  tenant_id            = "00000000-0000-0000-0000-000000000000"
  client_id            = "00000000-0000-0000-0000-000000000000"
  resource_group_name  = "rg-infraflow-prod"
  location             = "eastus"
  storage_account_name = "stinfraflowprod01"
  container_name       = "tfstate"
  environment          = "prod"
}

run "verify_azure_storage_configuration" {
  command = plan

  assert {
    condition     = azurerm_resource_group.rg.name == "rg-infraflow-prod"
    error_message = "Resource group name must match configured variable"
  }

  assert {
    condition     = azurerm_resource_group.rg.location == "eastus"
    error_message = "Resource group location must match configured location"
  }

  assert {
    condition     = azurerm_storage_account.storage.name == "stinfraflowprod01"
    error_message = "Storage account name must match configured variable"
  }

  assert {
    condition     = azurerm_storage_account.storage.min_tls_version == "TLS1_2"
    error_message = "min_tls_version must explicitly be TLS1_2"
  }

  assert {
    condition     = azurerm_storage_account.storage.allow_nested_items_to_be_public == false
    error_message = "allow_nested_items_to_be_public must be false"
  }

  assert {
    condition     = azurerm_storage_account.storage.public_network_access_enabled == false
    error_message = "public_network_access_enabled must be false"
  }

  assert {
    condition     = azurerm_storage_account.storage.shared_access_key_enabled == false
    error_message = "shared_access_key_enabled must be false"
  }

  assert {
    condition     = azurerm_storage_account.storage.blob_properties[0].versioning_enabled == true
    error_message = "Storage blob versioning must be enabled"
  }

  assert {
    condition     = azurerm_storage_container.tfstate.name == "tfstate"
    error_message = "Storage container name must match configured variable"
  }

  assert {
    condition     = azurerm_storage_container.tfstate.container_access_type == "private"
    error_message = "container_access_type must explicitly be private"
  }

  assert {
    condition     = azurerm_storage_account.storage.tags["environment"] == "prod"
    error_message = "environment tag must be prod"
  }

  assert {
    condition     = azurerm_storage_account.storage.tags["managed_by"] == "terraform"
    error_message = "managed_by tag must be terraform"
  }

  assert {
    condition     = azurerm_storage_account.storage.tags["project"] == "infraflow"
    error_message = "project tag must be infraflow"
  }
}
