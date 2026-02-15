# Vibe coded untested config

watch_item "OneDriveSync" do
  path "/Users/*/Library/CloudStorage/OneDrive-*/", prefix: true

  options do
    allow_read_access true
    audit_only true
    rule_type "PathsWithAllowedProcesses"
    block_message "OneDrive synced file access is being audited"
  end
end

watch_item "OneDriveData" do
  path "/Users/*/Library/Group Containers/UBF8T346G9.OneDriveStandaloneSuite/", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "OneDrive internal data is protected from unauthorized access"
  end

  process signing_id: "com.microsoft.OneDrive", team_id: "UBF8T346G9"
  process signing_id: "com.microsoft.OneDrive-mac", team_id: "UBF8T346G9"
end

watch_item "OfficeSharedData" do
  path "/Users/*/Library/Group Containers/UBF8T346G9.Office/", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "Microsoft Office shared data is protected from unauthorized access"
  end

  process signing_id: "com.microsoft.Word", team_id: "UBF8T346G9"
  process signing_id: "com.microsoft.Excel", team_id: "UBF8T346G9"
  process signing_id: "com.microsoft.Powerpoint", team_id: "UBF8T346G9"
  process signing_id: "com.microsoft.Outlook", team_id: "UBF8T346G9"
  process signing_id: "com.microsoft.onenote.mac", team_id: "UBF8T346G9"
  process signing_id: "com.microsoft.OneDrive", team_id: "UBF8T346G9"
  process signing_id: "com.microsoft.teams2", team_id: "UBF8T346G9"
  process signing_id: "com.apple.mds", platform_binary: true
end

watch_item "TeamsData" do
  path "/Users/*/Library/Group Containers/UBF8T346G9.com.microsoft.teams/", prefix: true
  path "/Users/*/Library/Containers/com.microsoft.teams2/", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "Microsoft Teams data is protected from unauthorized access"
  end

  process signing_id: "com.microsoft.teams2", team_id: "UBF8T346G9"
  process signing_id: "com.microsoft.teams", team_id: "UBF8T346G9"
end

watch_item "TeamsResources" do
  path "/Applications/Microsoft Teams.app/Contents/Resources/", prefix: true

  options do
    allow_read_access true
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "Microsoft Teams application resources are protected from modification"
  end

  process signing_id: "com.microsoft.teams2", team_id: "UBF8T346G9"
end

watch_item "OfficeAppResources" do
  path "/Applications/Microsoft Word.app/Contents/Resources/", prefix: true
  path "/Applications/Microsoft Excel.app/Contents/Resources/", prefix: true
  path "/Applications/Microsoft PowerPoint.app/Contents/Resources/", prefix: true
  path "/Applications/Microsoft Outlook.app/Contents/Resources/", prefix: true
  path "/Applications/Microsoft OneNote.app/Contents/Resources/", prefix: true

  options do
    allow_read_access true
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "Microsoft Office application resources are protected from modification"
  end

  process signing_id: "com.microsoft.autoupdate2", team_id: "UBF8T346G9"
end
