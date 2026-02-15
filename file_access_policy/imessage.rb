watch_item "iMessages" do
  path "/Users/*/Library/Messages/", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "iMessage database is protected from unauthorized access"
  end

  process signing_id: "com.apple.MobileSMS", platform_binary: true
  process signing_id: "com.apple.iChat", platform_binary: true
  process signing_id: "com.apple.mdworker_shared", platform_binary: true
  process signing_id: "com.apple.Spotlight", platform_binary: true
end
