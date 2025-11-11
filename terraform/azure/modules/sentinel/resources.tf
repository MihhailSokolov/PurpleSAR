resource "azurerm_log_analytics_workspace" "sentinel-law" {
  name                = "ar-sentinel-${var.general.key_name}-${var.general.attack_range_name}"
  location            = var.azure.location
  resource_group_name = var.rg_name
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

resource "azurerm_sentinel_log_analytics_workspace_onboarding" "sentinel" {
  workspace_id                 = azurerm_log_analytics_workspace.sentinel-law.id
  customer_managed_key_enabled = false
}

resource "azurerm_role_assignment" "vm-managed-identity-law-role-assignment" {
    count                = length(var.managed_identity_ids)
    scope                = azurerm_log_analytics_workspace.sentinel-law.id
    role_definition_name = "Log Analytics Contributor"
    principal_id         = var.managed_identity_ids[count.index]
}

resource "azurerm_virtual_machine_extension" "da" {
  count                      = length(var.windows_server_ids)
  name                       = "DependencyAgentWindows"
  auto_upgrade_minor_version = true
  automatic_upgrade_enabled  = true
  publisher                  = "Microsoft.Azure.Monitoring.DependencyAgent"
  type                       = "DependencyAgentWindows"
  type_handler_version       = "9.10"
  virtual_machine_id         = var.windows_server_ids[count.index]
}

resource "azurerm_virtual_machine_extension" "ama" {
  count                      = length(var.windows_server_ids)
  name                       = "AzureMonitorWindowsAgent"
  auto_upgrade_minor_version = true
  automatic_upgrade_enabled  = true
  publisher                  = "Microsoft.Azure.Monitor"
  type                       = "AzureMonitorWindowsAgent"
  type_handler_version       = "1.37"
  virtual_machine_id         = var.windows_server_ids[count.index]
}

resource "random_string" "dcr_suffix" {
  length  = 6
  special = false
  upper   = false
}

resource "azurerm_monitor_data_collection_rule" "sentinel-dcr" {
    name                = "ar-sentinel-dcr-${var.general.key_name}-${var.general.attack_range_name}"
    location            = var.azure.location
    resource_group_name = var.rg_name
    kind                = "Windows"

    destinations {
      log_analytics {
        name                  = "la--${random_string.dcr_suffix.result}"
        workspace_resource_id = azurerm_log_analytics_workspace.sentinel-law.id
      }
    }

    data_sources {
      windows_event_log {
        name           = "eventLogsDataSource"
        streams        = ["Microsoft-Event"]
        x_path_queries = ["Application!*[System[(Level=1 or Level=2 or Level=3 or Level=4 or Level=0)]]", 
                          "Security!*[System[(band(Keywords,13510798882111488))]]", 
                          "System!*[System[(Level=1 or Level=2 or Level=3 or Level=4 or Level=0)]]",
                          "Microsoft-Windows-Sysmon/Operational!*",
                          "Microsoft-Windows-Powershell/Operational!*",
                          "Microsoft-Windows-Windows Defender/Operational!*"]
      }
    }

    data_flow {
        streams       = ["Microsoft-Event"]
        destinations  = ["la--${random_string.dcr_suffix.result}"]
        output_stream = "Microsoft-Event"
        transform_kql = "source"
    }

}

resource "azurerm_monitor_data_collection_rule_association" "vm-dcr-association" {
  count                   = length(var.windows_server_ids)
  name                    = "sentinel-dcr-association"
  data_collection_rule_id = azurerm_monitor_data_collection_rule.sentinel-dcr.id
  target_resource_id      = var.windows_server_ids[count.index]
  depends_on = [azurerm_virtual_machine_extension.ama]
}