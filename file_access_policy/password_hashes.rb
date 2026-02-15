watch_item "PasswordHashes" do
  path "/var/db/dslocal/nodes/Default/users/", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "Password hash files are protected from unauthorized access"
  end

  process signing_id: "com.apple.opendirectoryd", platform_binary: true
  process signing_id: "com.apple.DirectoryService", platform_binary: true
end
