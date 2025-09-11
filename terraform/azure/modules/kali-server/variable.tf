
variable "rg_name" { }
variable "subnet_id" { }
variable "general" { }
variable "kali_server" { }
variable "kali_image" {
    default = {
        kali_publisher = "kali-linux",
        kali_offer = "kali",
        kali_sku = "kali-2025-2",
    }
}
variable "azure" { }