# Vibe coded untested config

watch_item "LaunchAgents" do
  path "/Library/LaunchAgents/", prefix: true
  path "/Users/*/Library/LaunchAgents/", prefix: true

  options do
    allow_read_access true
    audit_only true
    rule_type "PathsWithAllowedProcesses"
  end
end

watch_item "LaunchDaemons" do
  path "/Library/LaunchDaemons/", prefix: true

  options do
    allow_read_access true
    audit_only true
    rule_type "PathsWithAllowedProcesses"
  end
end
