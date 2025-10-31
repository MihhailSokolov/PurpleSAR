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

locals {
  queryFrequency = "PT5M"
  queryPeriod    = "PT5M"
}

resource "azurerm_sentinel_alert_rule_scheduled" "network_connection_certutil" {
  name = "Uncommon Network Connection Initiated By Certutil.EXE"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.sentinel-law.id
  display_name = "Uncommon Network Connection Initiated By Certutil.EXE"
  description = "net_connection_win_certutil_initiated_connection.yml\n\nhttps://github.com/SigmaHQ/sigma/blob/6fd57da13139643c6fe3e4a23276ca6ae9a6eec7/rules/windows/network_connection/net_connection_win_certutil_initiated_connection.yml#L2%5C"
  severity = "High"
  query = <<QUERY
// Certutil.exe initiating outbound network connections (ASIM Network Session)
_Im_NetworkSession()
| where EventType == "EndpointNetworkSession" 
| where DstProcessName contains "certutil" 
| where DstPortNumber in (80, 135, 443, 445)
QUERY
  tactics = ["CommandAndControl"]
  techniques = ["T1105"]
  query_frequency = local.queryFrequency
  query_period = local.queryPeriod
  depends_on = [ azurerm_sentinel_log_analytics_workspace_onboarding.sentinel ]
}

resource "azurerm_sentinel_alert_rule_scheduled" "real_time_monitoring_defender" {
  name = "Real-Time Protection in Defender disabled"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.sentinel-law.id
  display_name = "Real-Time Protection in Defender disabled"
  description = "win_defender_real_time_protection_disabled.yml\n\nhttps://github.com/SigmaHQ/sigma/blob/4f4ef7a8cc077b2b54c71c598db50fe8b1f14d55/rules/windows/builtin/windefend/win_defender_real_time_protection_disabled.yml#L4"
  severity = "Medium"
  query = <<QUERY
Event 
| where EventLog == "Microsoft-Windows-Windows Defender/Operational"
| where EventID == 5001
QUERY
  tactics = ["DefenseEvasion"]
  techniques = ["T1562"]
  query_frequency = local.queryFrequency
  query_period = local.queryPeriod
  depends_on = [ azurerm_sentinel_log_analytics_workspace_onboarding.sentinel ]
}

resource "azurerm_sentinel_alert_rule_scheduled" "rclone_process_execution" {
  name = "RClone Process Execution"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.sentinel-law.id
  display_name = "RClone Process Execution"
  description = "proc_creation_win_pua_rclone_execution.yml\n\nhttps://github.com/SigmaHQ/sigma/blob/d804e9cba10fa2e3bdabeca0cc330158c58de016/rules/windows/process_creation/proc_creation_win_pua_rclone_execution.yml#L4"
  severity = "Medium"
  query = <<QUERY
_ASim_ProcessEvent_Create
| where CommandLine has_any ("copy","ftp","pass","user","sync","config","lsd","remote","ls","mega","pcloud","ignore-existing","auto-confirm","transfers","multi-thread-streams","no-check-certificate", "--config")
| where TargetProcessFileCompany has "rclone" or TargetProcessFilename has "rclone"
QUERY
  tactics = ["Exfiltration"]
  techniques = ["T1567"]
  query_frequency = local.queryFrequency
  query_period = local.queryPeriod
  depends_on = [ azurerm_sentinel_log_analytics_workspace_onboarding.sentinel ]
}

resource "azurerm_sentinel_alert_rule_scheduled" "download_via_certutil" {
  name = "Suspicious Download Via Certutil.EXE"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.sentinel-law.id
  display_name = "Suspicious Download Via Certutil.EXE"
  description = "Detects the execution of certutil with certain flags that allow the utility to download files.\n\nproc_creation_win_certutil_download.yml\n\nhttps://github.com/SigmaHQ/sigma/blob/6fd57da13139643c6fe3e4a23276ca6ae9a6eec7/rules/windows/process_creation/proc_creation_win_certutil_download.yml"
  severity = "Medium"
  query = <<QUERY
// Suspicious Download Via Certutil.EXE — ASIM version
_Im_ProcessCreate() 
| where EventType == "ProcessCreated" // Normalized ProcessCreate schema from any source
| where Process endswith @"\certutil.exe" // Match certutil.exe by image or original file name
   or TargetProcessFileOriginalName =~ "CertUtil.exe"
| where CommandLine has_any ("urlcache ", "verifyctl ") // Command line flags
| where CommandLine contains "http" // and must contain http (download)
| project // Output key fields
    EventStartTime,
    DvcHostname,
    ActorUsername,
    Process,
    CommandLine,
    TargetProcessFileOriginalName,
    ParentProcessName,
    TargetProcessId
| order by EventStartTime desc
QUERY
  tactics = ["DefenseEvasion"]
  techniques = ["T1027"]
  query_frequency = local.queryFrequency
  query_period = local.queryPeriod
  depends_on = [ azurerm_sentinel_log_analytics_workspace_onboarding.sentinel ]
}

resource "azurerm_sentinel_alert_rule_scheduled" "domain_admin_pw_reset" {
  name = "Domain Admin Password Reset"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.sentinel-law.id
  display_name = "Domain Admin Password Reset"
  description = "win-ad-bruteforce via password reset.yaml\n\nhttps://github.com/mdecrevoisier/SIGMA-detection-rules/blob/2aca9946d75306e91f490b76c95abcae177dd71a/windows-active_directory/win-ad-bruteforce%20via%20password%20reset.yaml#L19."
  severity = "High"
  query = <<QUERY
Event 
| where EventLog == "Security"
| where EventID == 4724 
| mv-apply EventData = parse_xml(EventData).DataItem.EventData.Data on 
(
    where EventData["@Name"] ==  "TargetUserName"
    | project TargetUserName = EventData["#text"]
)
| where TargetUserName == "AzureAdmin"
QUERY
  tactics = ["CredentialAccess"]
  techniques = ["T1110"]
  query_frequency = local.queryFrequency
  query_period = local.queryPeriod
  depends_on = [ azurerm_sentinel_log_analytics_workspace_onboarding.sentinel ]
}

resource "azurerm_sentinel_alert_rule_scheduled" "ad_user_enumeration" {
  name = "Potential AD User Enumeration From Non-Machine Account"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.sentinel-law.id
  display_name = "Potential AD User Enumeration From Non-Machine Account"
  description = "Detects read access to a domain user from a non-machine account\n\nwin_security_ad_user_enumeration.yml\n\nhttps://github.com/SigmaHQ/sigma/blob/6fd57da13139643c6fe3e4a23276ca6ae9a6eec7/rules/windows/builtin/security/win_security_ad_user_enumeration.yml"
  severity = "Medium"
  query = <<QUERY
Event
| where EventLog == \"Security\"
| where EventID == 4662
| extend EventXml = parse_xml(EventData)
| mv-expand Data = EventXml.DataItem.EventData.Data
| extend Name = tostring(Data[\"@Name\"]), Value = tostring(Data[\"#text\"])
| summarize EventDataBag = make_bag(pack(Name, Value)) by TimeGenerated, Computer, EventID, EventLog
| extend    ObjectType = tostring(EventDataBag.ObjectType),
    AccessMask = tostring(EventDataBag.AccessMask),
    ObjectName = tostring(EventDataBag.ObjectName),
    SubjectUserName = tostring(EventDataBag.SubjectUserName),
    SubjectDomainName = tostring(EventDataBag.SubjectDomainName),
    SubjectLogonId = tostring(EventDataBag.SubjectLogonId),
    ObjectServer = tostring(EventDataBag.ObjectServer)
| where ObjectType contains \"bf967aba-0de6-11d0-a285-00aa003049e2\"
| where (
        AccessMask endswith \"1?\" or
        AccessMask endswith \"3?\" or 
        AccessMask endswith \"4?\" or 
        AccessMask endswith \"7?\" or
        AccessMask endswith \"9?\" or
        AccessMask endswith \"B?\" or
        AccessMask endswith \"D?\" or
        AccessMask endswith \"F?\"
        )
| where SubjectUserName !endswith \"$\"
QUERY
  tactics = ["Discovery"]
  techniques = ["T1087"]
  query_frequency = local.queryFrequency
  query_period = local.queryPeriod
  depends_on = [ azurerm_sentinel_log_analytics_workspace_onboarding.sentinel ]
}

resource "azurerm_sentinel_alert_rule_scheduled" "credential_dumping_werfault" {
  name = "Credential Dumping Attempt Via WerFault"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.sentinel-law.id
  display_name = "Credential Dumping Attempt Via WerFault"
  description = "proc_access_win_lsass_werfault.yml\n\nhttps://github.com/SigmaHQ/sigma/blob/a77d3bae4bbe6eae5b9fae7b598bf9c7734424bc/rules/windows/process_access/proc_access_win_lsass_werfault.yml#L4"
  severity = "High"
  query = <<QUERY
Event
| where EventLog == \"Microsoft-Windows-Sysmon/Operational\"
| where EventID == 10 
| extend EventXml = parse_xml(EventData)
| mv-expand Data = EventXml.DataItem.EventData.Data
| extend Name = tostring(Data[\"@Name\"]), Value = tostring(Data[\"#text\"])
| summarize EventDataBag = make_bag(pack(Name, Value)) by TimeGenerated, Computer, EventID, EventLog
| extend
    SourceImage = tostring(EventDataBag.SourceImage),
    TargetImage = tostring(EventDataBag.TargetImage),
    GrantedAccess = tostring(EventDataBag.GrantedAccess)
| where SourceImage endswith \"\\\\WerFault.exe\"
| where TargetImage endswith \"\\\\lsass.exe\"
| where GrantedAccess == \"0x1FFFFF\"
QUERY
  tactics = ["CredentialAccess"]
  techniques = ["T1003"]
  query_frequency = local.queryFrequency
  query_period = local.queryPeriod
  depends_on = [ azurerm_sentinel_log_analytics_workspace_onboarding.sentinel ]
}

resource "azurerm_sentinel_alert_rule_scheduled" "mimikatz_lsass_access" {
  name = "Mimikatz Detection LSASS Access"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.sentinel-law.id
  display_name = "Mimikatz Detection LSASS Access"
  description = "sysmon_mimikatz_detection_lsass.yml\n\nhttps://github.com/SigmaHQ/sigma/blob/a77d3bae4bbe6eae5b9fae7b598bf9c7734424bc/deprecated/windows/sysmon_mimikatz_detection_lsass.yml#L4"
  severity = "High"
  query = <<QUERY
Event
| where EventLog == \"Microsoft-Windows-Sysmon\"
| where EventID == 10
| extend EventXml = parse_xml(EventData)
| mv-expand Data = EventXml.DataItem.EventData.Data
| extend Name = tostring(Data[\"@Name\"]), Value = tostring(Data[\"#text\"])
| summarize EventDataBag = make_bag(pack(Name, Value)) by TimeGenerated, Computer, EventID, EventLog
| extend
    SourceImage = tostring(EventDataBag.SourceImage),
    TargetImage = tostring(EventDataBag.TargetImage),
    GrantedAccess = tostring(EventDataBag.GrantedAccess),
    User = tostring(EventDataBag.User)
| where TargetImage endswith \"\\\\lsass.exe\"
| where GrantedAccess in (\"0x1410\", \"0x1010\", \"0x410\")
| where not (
        (SourceImage startswith \"C:\\\\Program Files\\\\WindowsApps\\\\\"
        or SourceImage startswith \"C:\\\\Windows\\\\System32\\\\\")
        and SourceImage endswith \"\\\\GamingServices.exe\"
    )
QUERY
  tactics = ["CredentialAccess"]
  techniques = ["T1003"]
  query_frequency = local.queryFrequency
  query_period = local.queryPeriod
  depends_on = [ azurerm_sentinel_log_analytics_workspace_onboarding.sentinel ]
}

resource "azurerm_sentinel_alert_rule_scheduled" "ad_privileged_user_group_recon" {
  name = "AD Privileged Users or Groups Reconnaissance"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.sentinel-law.id
  display_name = "AD Privileged Users or Groups Reconnaissance"
  description = "win_security_account_discovery.yml\n\nhttps://github.com/SigmaHQ/sigma/blob/a77d3bae4bbe6eae5b9fae7b598bf9c7734424bc/rules/windows/builtin/security/win_security_account_discovery.yml#L4"
  severity = "High"
  query = <<QUERY
Event
| where EventLog == \"Microsoft-Windows-Security-Auditing\"
| where EventID == 4661
| extend EventXml = parse_xml(EventData)
| mv-expand Data = EventXml.DataItem.EventData.Data
| extend Name = tostring(Data[\"@Name\"]), Value = tostring(Data[\"#text\"])
| summarize EventDataBag = make_bag(pack(Name, Value)) by TimeGenerated, Computer, EventID, EventLog
| extend
    ObjectType = tostring(EventDataBag.ObjectType),
    ObjectName = tostring(EventDataBag.ObjectName),
    SubjectUserName = tostring(EventDataBag.SubjectUserName),
    SubjectDomainName = tostring(EventDataBag.SubjectDomainName),
    SubjectLogonId = tostring(EventDataBag.SubjectLogonId),
    ObjectServer = tostring(EventDataBag.ObjectServer)
| where ObjectType in (\"SAM_USER\", \"SAM_GROUP\")
| where (
        ObjectName endswith \"-512\" or
        ObjectName endswith \"-502\" or
        ObjectName endswith \"-500\" or
        ObjectName endswith \"-505\" or
        ObjectName endswith \"-519\" or
        ObjectName endswith \"-520\" or
        ObjectName endswith \"-544\" or
        ObjectName endswith \"-551\" or
        ObjectName endswith \"-555\" or
        ObjectName contains \"admin\"
    )
| where SubjectUserName !endswith \"$\"
QUERY
  tactics = ["Discovery"]
  techniques = ["T1087"]
  query_frequency = local.queryFrequency
  query_period = local.queryPeriod
  depends_on = [ azurerm_sentinel_log_analytics_workspace_onboarding.sentinel ]
}

resource "azurerm_sentinel_alert_rule_scheduled" "password_dumping_activity_lsass" {
  name = "Password Dumper Activity on LSASS"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.sentinel-law.id
  display_name = "Password Dumper Activity on LSASS"
  description = "Detects process handle on LSASS process with certain access mask and object type SAM_DOMAIN\n\nwin_security_susp_lsass_dump.yml\n\nhttps://github.com/SigmaHQ/sigma/blob/6fd57da13139643c6fe3e4a23276ca6ae9a6eec7/rules/windows/builtin/security/win_security_susp_lsass_dump.yml"
  severity = "Medium"
  query = <<QUERY
Event
| where EventID == 4656
| where EventData has_all (\"lsass.exe\", \"SAM_DOMAIN\", \"0x705\")
QUERY
  tactics = ["CredentialAccess"]
  techniques = ["T1003"]
  query_frequency = local.queryFrequency
  query_period = local.queryPeriod
  depends_on = [ azurerm_sentinel_log_analytics_workspace_onboarding.sentinel ]
}

resource "azurerm_sentinel_alert_rule_scheduled" "mimikatz_keywords" {
  name = "Mimikatz Use (Keywords)"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.sentinel-law.id
  display_name = "Mimikatz Use (Keywords)"
  description = "win_alert_mimikatz_keywords.yml\n\nhttps://github.com/SigmaHQ/sigma/blob/a77d3bae4bbe6eae5b9fae7b598bf9c7734424bc/rules/windows/builtin/win_alert_mimikatz_keywords.yml#L4"
  severity = "Medium"
  query = <<QUERY
let mimikatz_keywords = dynamic([
    \"dpapi::masterkey\",
    \"eo.oe.kiwi\",
    \"event::clear\",
    \"event::drop\",
    \"gentilkiwi.com\",
    \"kerberos::golden\",
    \"kerberos::ptc\",
    \"kerberos::ptt\",
    \"kerberos::tgt\",
    \"kiwi legit printer\",
    \"lsadump::\",
    \"mimidrv.sys\",
    \"\\\\mimilib.dll\",
    \"misc::printnightmare\",
    \"misc::shadowcopies\",
    \"misc::skeleton\",
    \"privilege::backup\",
    \"privilege::debug\",
    \"privilege::driver\",
    \"sekurlsa::\"
]);

Event
| where EventLog startswith \"Microsoft\"
| where not (EventID == 15 and EventLog == \"Microsoft-Windows-Sysmon\")
| extend FullText = strcat(EventData, \" \", tostring(RenderedDescription))
| where FullText has_any (mimikatz_keywords)
QUERY
  tactics = ["CredentialAccess"]
  techniques = ["T1003"]
  query_frequency = local.queryFrequency
  query_period = local.queryPeriod
  depends_on = [ azurerm_sentinel_log_analytics_workspace_onboarding.sentinel ]
}

resource "azurerm_sentinel_alert_rule_scheduled" "generic_hacktool_process_access" {
  name = "HackTool - Generic Process Access"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.sentinel-law.id
  display_name = "HackTool - Generic Process Access"
  description = "proc_access_win_hktl_generic_access.yml\nhttps://github.com/SigmaHQ/sigma/blob/a77d3bae4bbe6eae5b9fae7b598bf9c7734424bc/rules/windows/process_access/proc_access_win_hktl_generic_access.yml#L4"
  severity = "High"
  query = <<QUERY
let hacktool_terms = dynamic([
\"akagi.exe\",\"akagi64.exe\",\"atexec_windows.exe\",\"certify.exe\",\"certipy.exe\",\"coercedpotato.exe\",
\"crackmapexec.exe\",\"createminidump.exe\",\"dcomexec_windows.exe\",\"dpapi_windows.exe\",\"finddelegation_windows.exe\",
\"getadusers_windows.exe\",\"getnpusers_windows.exe\",\"getpac_windows.exe\",\"getst_windows.exe\",\"gettgt_windows.exe\",
\"getuserspns_windows.exe\",\"gmer.exe\",\"hashcat.exe\",\"htran.exe\",\"ifmap_windows.exe\",\"impersonate.exe\",
\"inveigh.exe\",\"localpotato.exe\",\"mimikatz_windows.exe\",\"mimikatz.exe\",\"netview_windows.exe\",\"nmapanswermachine_windows.exe\",
\"opdump_windows.exe\",\"passworddump.exe\",\"potato.exe\",\"powertool.exe\",\"powertool64.exe\",\"psexec_windows.exe\",
\"purplesharp.exe\",\"pypykatz.exe\",\"quarkspwdump.exe\",\"rdp_check_windows.exe\",\"rubeus.exe\",\"safetykatz.exe\",
\"sambapipe_windows.exe\",\"selectmyparent.exe\",\"sharpchisel.exe\",\"sharpersist.exe\",\"sharpevtmute.exe\",
\"sharpimpersonation.exe\",\"sharpldapmonitor.exe\",\"sharpldapwhoami.exe\",\"sharpup.exe\",\"sharpview.exe\",
\"smbclient_windows.exe\",\"smbserver_windows.exe\",\"sniff_windows.exe\",\"sniffer_windows.exe\",\"split_windows.exe\",
\"spoolsample.exe\",\"stracciatella.exe\",\"sysmoneop.exe\",\"rot.exe\",\"ticketer_windows.exe\",\"trufflesnout.exe\",
\"winpeasany_ofs.exe\",\"winpeasany.exe\",\"winpeasx64_ofs.exe\",\"winpeasx64.exe\",\"winpeasx86_ofs.exe\",\"winpeasx86.exe\",
\"xordump.exe\",
\"goldenpac\",\"just_dce_\",\"karmasmb\",\"kintercept\",\"ntlmrelayx\",\"rpcdump\",\"samrdump\",\"secretsdump\",
\"smbexec\",\"smbrelayx\",\"wmiexec\",\"wmipersist\",\"hotpotato\",\"juicy potato\",\"juicypotato\",\"petitpotam\",\"rottenpotato\"
]);

Event 
| where EventLog == \"Microsoft-Windows-Sysmon/Operational\"
| where EventID == 10 
| mv-apply EventData = parse_xml(EventData).DataItem.EventData.Data on 
    (
    where EventData[\"@Name\"] == \"SourceImage\"
    | project SourceImage = EventData[\"#text\"]
    )
| where SourceImage has_any(hacktool_terms)
QUERY
  tactics = ["CredentialAccess"]
  techniques = ["T1003"]
  query_frequency = local.queryFrequency
  query_period = local.queryPeriod
  depends_on = [ azurerm_sentinel_log_analytics_workspace_onboarding.sentinel ]
}

resource "azurerm_sentinel_alert_rule_scheduled" "mimikatz_kirbi_file_creation" {
  name = "HackTool - Mimikatz Kirbi File Creation"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.sentinel-law.id
  display_name = "HackTool - Mimikatz Kirbi File Creation"
  description = "file_event_win_hktl_mimikatz_files.yml\nhttps://github.com/SigmaHQ/sigma/blob/4f4ef7a8cc077b2b54c71c598db50fe8b1f14d55/rules/windows/file/file_event/file_event_win_hktl_mimikatz_files.yml#L4"
  severity = "High"
  query = <<QUERY
_Im_FileEvent()
| where TargetFileName endswith \".kirbi\" or TargetFileName endswith \"mimilsa.log\"
QUERY
  tactics = ["CredentialAccess"]
  query_frequency = local.queryFrequency
  query_period = local.queryPeriod
  depends_on = [ azurerm_sentinel_log_analytics_workspace_onboarding.sentinel ]
}

resource "azurerm_sentinel_alert_rule_scheduled" "tamper_protection_defender" {
  name = "Microsoft Defender Tamper Protection Trigger"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.sentinel-law.id
  display_name = "Microsoft Defender Tamper Protection Trigger"
  description = "win_defender_tamper_protection_trigger.yml\nhttps://github.com/SigmaHQ/sigma/blob/4f4ef7a8cc077b2b54c71c598db50fe8b1f14d55/rules/windows/builtin/windefend/win_defender_tamper_protection_trigger.yml#L4"
  severity = "High"
  query = <<QUERY
Event
| where EventLog == \"Microsoft-Windows-Windows Defender/Operational\"
| where EventID == 5013
QUERY
  tactics = ["DefenseEvasion"]
  techniques = ["T1562"]
  query_frequency = local.queryFrequency
  query_period = local.queryPeriod
  depends_on = [ azurerm_sentinel_log_analytics_workspace_onboarding.sentinel ]
}

resource "azurerm_sentinel_alert_rule_scheduled" "bloodhound_collection_files" {
  name = "BloodHound Collection Files"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.sentinel-law.id
  display_name = "BloodHound Collection Files"
  description = "file_event_win_bloodhound_collection.yml\nhttps://github.com/SigmaHQ/sigma/blob/1f1f31e99c3c1dd2ac21f471ca7ec67a923c3e87/rules/windows/file/file_event/file_event_win_bloodhound_collection.yml#L4"
  severity = "High"
  query = <<QUERY
_Im_FileEvent()
| where 
(
    (TargetFileName has_any (\"BloodHound.zip\", \"_computers.json\", \"_containers.json\", \"_domains.json\", \"_gpos.json\", \"_groups.json\", \"_ous.json\", \"_users.json\"))
    and
    not(FileName contains \"svchost.exe\" or TargetFileName startswith \"C:\\\\Program Files\\\\WindowsApps\\\\Microsoft.\" or TargetFileName  endswith \"pocket_containers.json\")
)
QUERY
  tactics = ["Discovery", "Execution"]
  techniques = ["T1087", "T1482", "T1069", "T1059"]
  query_frequency = local.queryFrequency
  query_period = local.queryPeriod
  depends_on = [ azurerm_sentinel_log_analytics_workspace_onboarding.sentinel ]
}

resource "azurerm_sentinel_alert_rule_scheduled" "net_exe_group_account_recon" {
  name = "Suspicious Group And Account Reconnaissance Activity Using Net.EXE"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.sentinel-law.id
  display_name = "Suspicious Group And Account Reconnaissance Activity Using Net.EXE"
  description = "proc_creation_win_net_groups_and_accounts_recon.yml\nhttps://github.com/SigmaHQ/sigma/blob/1f1f31e99c3c1dd2ac21f471ca7ec67a923c3e87/rules/windows/process_creation/proc_creation_win_net_groups_and_accounts_recon.yml#L17"
  severity = "Low"
  query = <<QUERY
_Im_ProcessCreate()
| where EventType == \"ProcessCreated\"
| extend
    Proc     = tostring(Process),
    Cmd      = tostring(CommandLine),
    OrigName = tostring(TargetProcessFileOriginalName),
    Product  = tostring(TargetProcessFileProduct),
    Company  = tostring(TargetProcessFileCompany),
    FileDesc = tostring(TargetProcessFileDescription)
| where 
(
    (Proc has_any(\"net.exe\", \"net1.exe\"))
    or
    (tolower(OrigName) has_any(\"net.exe\", \"net1.exe\"))
)
and
(
    (
        (
            (Cmd has_any(\" group \", \" localgroup\"))
            or 
            (Cmd contains \"domain admins\" or Cmd contains \" administrator\" or Cmd contains \"enterprise admins\" or Cmd contains \"Exchange Trusted Subsystem\" or Cmd contains \"Remote Desktop Users\" or Cmd contains \" /do\")
        )
        and
        (
            not(Cmd contains \"/add\")
        )
    )
    or 
    (
        (Cmd contains \" accounts \")
        and 
        (Cmd contains \" /do\")
    )
)
QUERY
  tactics = ["Discovery"]
  techniques = ["T1087"]
  query_frequency = local.queryFrequency
  query_period = local.queryPeriod
  depends_on = [ azurerm_sentinel_log_analytics_workspace_onboarding.sentinel ]
}

resource "azurerm_sentinel_alert_rule_scheduled" "shadow_copy_deletion" {
  name = "Shadow Copies Deletion"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.sentinel-law.id
  display_name = "Shadow Copies Deletion"
  description = "proc_creation_win_susp_shadow_copies_deletion.yml\nhttps://github.com/SigmaHQ/sigma/blob/d804e9cba10fa2e3bdabeca0cc330158c58de016/rules/windows/process_creation/proc_creation_win_susp_shadow_copies_deletion.yml#L9"
  severity = "High"
  query = <<QUERY
_Im_FileEvent()
_Im_ProcessCreate
| where 
    (
        (TargetProcessName has_any (\"powershell.exe\", \"pwsh.exe\", \"wmic.exe\", \"vssadmin.exe\", \"diskshadow.exe\", \"wbadmin.exe\") or 
            TargetProcessFilename has_any (\"PowerShell.EXE\", \"pwsh.  dll\", \"wmic.exe\", \"VSSADMIN.EXE\", \"diskshadow.exe\", \"WBADMIN.EXE\"))
        and 
        (CommandLine has \"delete\" and CommandLine contains \"shadow\")
    )
    or
    (
        (TargetProcessName has (\"wbadmin.exe\") or TargetProcessFilename has (\"WBADMIN.EXE\"))
        and 
        (CommandLine has_all (\"delete\", \"catalog\", \"quiet\"))
    )
    or
    (
        (TargetProcessName has (\"vssadmin.exe\") or TargetProcessFilename has (\"VSSADMIN.EXE\"))
        and 
        (
            (CommandLine has_all (\"resize\", \"shadowstorage\"))
            or
            (CommandLine has_any (\"unbounded\", \"/MaxSize=\"))
        )
    )

QUERY
  tactics = ["DefenseEvasion", "Impact"]
  query_frequency = local.queryFrequency
  query_period = local.queryPeriod
  depends_on = [ azurerm_sentinel_log_analytics_workspace_onboarding.sentinel ]
}

resource "azurerm_sentinel_alert_rule_scheduled" "bloodhound_sharphound_execution" {
  name = "HackTool - Bloodhound/Sharphound Execution"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.sentinel-law.id
  display_name = "HackTool - Bloodhound/Sharphound Execution"
  description = "Detects command line parameters used by Bloodhound and Sharphound hack tools\n\nproc_creation_win_hktl_bloodhound_sharphound.yml\n\nhttps://github.com/SigmaHQ/sigma/blob/6fd57da13139643c6fe3e4a23276ca6ae9a6eec7/rules/windows/process_creation/proc_creation_win_hktl_bloodhound_sharphound.yml"
  severity = "High"
  query = <<QUERY
// HackTool - Bloodhound/SharpHound Execution — ASIM (fixed: no mid-pipeline let)
_Im_ProcessCreate()                                    // use your parser name if different
| where EventType == \"ProcessCreated\"
| extend
    Proc     = tostring(Process),
    Cmd      = tostring(CommandLine),
    OrigName = tostring(TargetProcessFileOriginalName),
    Product  = tostring(TargetProcessFileProduct),
    Company  = tostring(TargetProcessFileCompany),
    FileDesc = tostring(TargetProcessFileDescription)
| extend
    // selection_img
    sel_img =
        (Proc has_any (\"\\\\Bloodhound.exe\", \"\\\\SharpHound.exe\")
         or tolower(OrigName) has \"bloodhound\"
         or tolower(OrigName) has \"sharphound\"
         or tolower(Product)  has_any (\"bloodhound\",\"sharphound\")
         or tolower(FileDesc) has \"sharphound\"
         or tolower(Company)  has_any (\"specterops\",\"evil corp\")),
    // selection_cli_1 (any)
    sel_cli_1 = Cmd has_any (
         \" -CollectionMethod All \",
         \" --CollectionMethods Session \",
         \" --Loop --Loopduration \",
         \" --PortScanTimeout \",
         \".exe -c All -d \",
         \"Invoke-Bloodhound\",
         \"Get-BloodHoundData\"),
    // selection_cli_2 (all)
    sel_cli_2 = (Cmd contains \" -JsonFolder \" and Cmd contains \" -ZipFileName \"),
    // selection_cli_3 (all)
    sel_cli_3 = (Cmd contains \" DCOnly \" and Cmd contains \" --NoSaveCache \")
| where sel_img or sel_cli_1 or sel_cli_2 or sel_cli_3   // Sigma: 1 of selection_*
| project
    EventStartTime, DvcHostname, ActorUsername,
    Proc, OrigName, Product, Company, FileDesc, Cmd,
    ParentProcessName, TargetProcessId
| order by EventStartTime desc
QUERY
  tactics = ["Discovery"]
  techniques = ["T1087", "T1482", "T1069"]
  query_frequency = local.queryFrequency
  query_period = local.queryPeriod
  depends_on = [ azurerm_sentinel_log_analytics_workspace_onboarding.sentinel ]
}

resource "azurerm_sentinel_alert_rule_scheduled" "file_sharing_download_certutil" {
  name = "Suspicious File Downloaded From File-Sharing Website Via Certutil.EXE"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.sentinel-law.id
  display_name = "Suspicious File Downloaded From File-Sharing Website Via Certutil.EXE"
  description = "Detects the execution of certutil with certain flags that allow the utility to download files from file-sharing websites.\n\nproc_creation_win_certutil_download_file_sharing_domains.yml\n\nhttps://github.com/SigmaHQ/sigma/blob/6fd57da13139643c6fe3e4a23276ca6ae9a6eec7/rules/windows/process_creation/proc_creation_win_certutil_download_file_sharing_domains.yml"
  severity = "High"
  query = <<QUERY
// Suspicious File Downloaded From File-Sharing Website Via certutil.exe (ASIM)
_Im_ProcessCreate()
| where EventType == \"ProcessCreated\" 
| where Process endswith @\"\\certutil.exe\" // Match certutil by image path or original filename
   or TargetProcessFileOriginalName =~ \"CertUtil.exe\" 
| where CommandLine has_any (\"urlcache \", \"verifyctl \") // Flags that enable downloads (as in the Sigma rule)
| where CommandLine has_any (\".githubusercontent.com\", \"anonfiles.com\", \"cdn.discordapp.com\", \"ddns.net\", \"dl.dropboxusercontent.com\", \"ghostbin.co\", \"glitch.me\", \"gofile.io\", \"hastebin.com\", \"mediafire.com\", \"mega.nz\", \"onrender.com\", \"pages.dev\", \"paste.ee\", \"pastebin.com\", \"pastebin.pl\", \"pastetext.net\", \"privatlab.com\", \"privatlab.net\", \"send.exploit.in\", \"sendspace.com\", \"storage.googleapis.com\", \"storjshare.io\", \"supabase.co\", \"temp.sh\", \"transfer.sh\", \"trycloudflare.com\", \"ufile.io\", \"w3spaces.com\", \"workers.dev\") // File-sharing / hosting domains (Sigma list)
| project // Output useful fields
    EventStartTime,
    DvcHostname,
    ActorUsername,
    Process,
    TargetProcessFileOriginalName,
    CommandLine,
    ParentProcessName,
    TargetProcessId
| order by EventStartTime desc

QUERY
  tactics = ["DefenseEvasion"]
  techniques = ["T1027"]
  query_frequency = local.queryFrequency
  query_period = local.queryPeriod
  depends_on = [ azurerm_sentinel_log_analytics_workspace_onboarding.sentinel ]
}