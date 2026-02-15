# Vibe coded untested config

watch_item "PAMConfiguration" do
  path "/etc/pam.d/", prefix: true

  options do
    allow_read_access true
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "Modification of PAM configuration files is not allowed"
  end
end
