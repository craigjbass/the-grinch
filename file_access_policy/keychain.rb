watch_item "UserKeychains" do
  path "/Users/*/Library/Keychains/", prefix: true

  options do
    allow_read_access false
    audit_only true
    rule_type "PathsWithAllowedProcesses"
  end

  process signing_id: "com.apple.securityd", platform_binary: true
  process signing_id: "com.apple.SecurityAgent", platform_binary: true
  process signing_id: "com.apple.authd", platform_binary: true
end

watch_item "SystemKeychains" do
  path "/Library/Keychains/", prefix: true

  options do
    allow_read_access false
    audit_only true
    rule_type "PathsWithAllowedProcesses"
  end

  process signing_id: "com.apple.securityd", platform_binary: true
  process signing_id: "com.apple.SecurityAgent", platform_binary: true
  process signing_id: "com.apple.authd", platform_binary: true
end
