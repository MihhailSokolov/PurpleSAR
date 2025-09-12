# VM IDs for Azure extension installation / DCR association
output "vm_ids" {
  value = azurerm_virtual_machine.windows[*].id
}

# Export system assigned managed identities
output "managed_identity_ids" {
    value = azurerm_virtual_machine.windows[*].identity[0].principal_id
}