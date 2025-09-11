resource "azurerm_public_ip" "kali-publicip" {
  count       = var.kali_server.kali_server == "1" ? 1 : 0
  name                = "ar-kali-ip-${var.general.key_name}"
  location            = var.azure.location
  resource_group_name = var.rg_name
  allocation_method   = "Static"
}

resource "azurerm_network_interface" "kali-nic" {
  count       = var.kali_server.kali_server == "1" ? 1 : 0
  name                = "ar-kali-nic-${var.general.key_name}"
  location            = var.azure.location
  resource_group_name = var.rg_name

  ip_configuration {
    name                          = "ar-kali-nic-conf-${var.general.key_name}"
    subnet_id                     = var.subnet_id
    private_ip_address_allocation = "Static"
    private_ip_address            = "10.0.1.30"
    public_ip_address_id          = azurerm_public_ip.kali-publicip[count.index].id
  }
}

resource "azurerm_marketplace_agreement" "kali_terms" {
  publisher = var.kali_image.kali_publisher
  offer     = var.kali_image.kali_offer
  plan      = var.kali_image.kali_sku
}

resource "azurerm_virtual_machine" "kali" {
  count       = var.kali_server.kali_server == "1" ? 1 : 0
  name = "ar-kali-${var.general.key_name}"
  location = var.azure.location
  resource_group_name  = var.rg_name
  network_interface_ids = [azurerm_network_interface.kali-nic[count.index].id]
  vm_size               = "Standard_D4_v4"

  delete_os_disk_on_termination = true

  storage_os_disk {
    name              = "disk-kali-${var.general.key_name}"
    caching           = "ReadWrite"
    create_option     = "FromImage"
    managed_disk_type = "Standard_LRS"
  }

  plan {
    publisher = var.kali_image.kali_publisher
    product   = var.kali_image.kali_offer
    name      = var.kali_image.kali_sku
  }

  storage_image_reference {
    publisher = var.kali_image.kali_publisher
    offer     = var.kali_image.kali_offer
    sku       = var.kali_image.kali_sku
    version   = "latest"
  }

  os_profile {
    computer_name  = "azure-kali"
    admin_username = "kali"
    admin_password = var.general.attack_range_password
  }

  os_profile_linux_config {
    disable_password_authentication = true
    ssh_keys {
      path     = "/home/kali/.ssh/authorized_keys"
      key_data = file(var.azure.public_key_path)
    }
  }

  provisioner "remote-exec" {
    inline = ["echo booted"]

    connection {
      type        = "ssh"
      user        = "kali"
      host        = azurerm_public_ip.kali-publicip[count.index].ip_address
      private_key = file(var.azure.private_key_path)
    }
  }

  provisioner "local-exec" {
  working_dir = "../ansible"
  command = <<-EOT
    cat <<EOF > vars/kali_vars.json
    {
      "general": ${jsonencode(var.general)},
      "aws": ${jsonencode(var.azure)},
      "kali_server": ${jsonencode(var.kali_server)}
    }
    EOF
  EOT
  }

  provisioner "local-exec" {
    working_dir = "../ansible"
    command = "ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -u kali --private-key '${var.azure.private_key_path}' -i '${azurerm_public_ip.kali-publicip[0].ip_address},' kali_server.yml -e @vars/kali_vars.json"
  }
}