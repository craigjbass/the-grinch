watch_item "1PasswordData" do
  path "/Users/*/Library/Group Containers/2BUA8C4S2C.com.1password/", prefix: true
  path "/Users/*/Library/Application Support/1Password/", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "1Password data is protected from unauthorized access"
  end

  process signing_id: "com.1password.1password", team_id: "2BUA8C4S2C"
  process signing_id: "com.1password.1password.helper", team_id: "2BUA8C4S2C"
  process signing_id: "com.1password.browser-support", team_id: "2BUA8C4S2C"
  process signing_id: "com.apple.mdworker_shared", platform_binary: true
end
