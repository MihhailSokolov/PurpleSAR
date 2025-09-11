# Configure the Microsoft Azure Provider
provider "azurerm" {
  subscription_id = var.azure.subscription_id
  features {}
}