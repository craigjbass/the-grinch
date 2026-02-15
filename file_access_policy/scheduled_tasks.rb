watch_item "ScheduledTasks" do
  path "/private/var/at/", prefix: true
  path "/usr/lib/cron/", prefix: true
  path "/var/at/tabs/", prefix: true

  options do
    allow_read_access true
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "Modification of scheduled tasks is not allowed"
  end

  process signing_id: "com.apple.cron", platform_binary: true
end
