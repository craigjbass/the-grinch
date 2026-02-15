watch_item "SystemAudioPlugins" do
  path "/Library/Audio/Plug-Ins/", prefix: true

  options do
    allow_read_access true
    audit_only true
    rule_type "PathsWithAllowedProcesses"
  end
end

watch_item "UserAudioPlugins" do
  path "/Users/*/Library/Audio/Plug-Ins/", prefix: true

  options do
    allow_read_access true
    audit_only true
    rule_type "PathsWithAllowedProcesses"
  end
end
