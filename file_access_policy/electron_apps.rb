watch_item "SlackResources" do
  path "/Applications/Slack.app/Contents/Resources/", prefix: true

  options do
    allow_read_access true
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "Slack application resources are protected from modification"
  end

  process signing_id: "com.tinyspeck.slackmacgap", team_id: "BQR82RBBHL"
end

watch_item "VSCodeResources" do
  path "/Applications/Visual Studio Code.app/Contents/Resources/", prefix: true

  options do
    allow_read_access true
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "VS Code application resources are protected from modification"
  end

  process signing_id: "com.microsoft.VSCode", team_id: "UBF8T346G9"
end

watch_item "DiscordResources" do
  path "/Applications/Discord.app/Contents/Resources/", prefix: true

  options do
    allow_read_access true
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "Discord application resources are protected from modification"
  end

  process signing_id: "com.hnc.Discord", team_id: "53Q6R32WPB"
end

watch_item "1PasswordDesktopResources" do
  path "/Applications/1Password.app/Contents/Resources/", prefix: true

  options do
    allow_read_access true
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "1Password application resources are protected from modification"
  end

  process signing_id: "com.1password.1password", team_id: "2BUA8C4S2C"
end

watch_item "NotionResources" do
  path "/Applications/Notion.app/Contents/Resources/", prefix: true

  options do
    allow_read_access true
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "Notion application resources are protected from modification"
  end

  process signing_id: "notion.id", team_id: "LBQJ96FQ8D"
end

watch_item "FigmaResources" do
  path "/Applications/Figma.app/Contents/Resources/", prefix: true

  options do
    allow_read_access true
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "Figma application resources are protected from modification"
  end

  process signing_id: "com.figma.Desktop", team_id: "T8RA8NE3B7"
end
