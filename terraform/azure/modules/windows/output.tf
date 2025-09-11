# VM IDs for Azure extension installation / DCR association
output "vm_ids" {
  value = azurerm_virtual_machine.windows[*].id
}