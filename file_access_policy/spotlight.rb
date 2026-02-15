watch_item "SpotlightImporters" do
  path "/Library/Spotlight/", prefix: true

  options do
    allow_read_access true
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "Spotlight importer directories are protected from modification"
  end

  process signing_id: "com.apple.Spotlight", platform_binary: true
  process signing_id: "com.apple.mdworker_shared", platform_binary: true
end

watch_item "CoreSpotlightIndex" do
  path "/Users/*/Library/Metadata/CoreSpotlight/", prefix: true

  options do
    allow_read_access true
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "CoreSpotlight index is protected from modification"
  end

  process signing_id: "com.apple.Spotlight", platform_binary: true
  process signing_id: "com.apple.mdworker_shared", platform_binary: true
end
