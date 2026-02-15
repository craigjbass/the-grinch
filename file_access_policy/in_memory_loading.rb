watch_item "InMemoryCodeLoading" do
  path "/private/tmp/NSCreateObjectFileImageFromMemory-", prefix: true
  path "/tmp/NSCreateObjectFileImageFromMemory-", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "Reflective code loading via NSCreateObjectFileImageFromMemory is blocked"
  end
end
