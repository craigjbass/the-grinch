watch_item "SSHKeys" do
  path "/Users/*/.ssh/", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "SSH keys are protected from unauthorized access"
  end

  process signing_id: "com.apple.openssh", platform_binary: true
  process signing_id: "com.apple.Terminal", platform_binary: true
  process signing_id: "com.apple.dt.Xcode", team_id: "59GAB85EFG"
  process signing_id: "dev.warp.Warp-Stable", team_id: "QKE527SSM6"
  process signing_id: "com.googlecode.iterm2", team_id: "H7V7XYVQ7D"
  process signing_id: "com.microsoft.VSCode", team_id: "UBF8T346G9"
  process signing_id: "com.todesktop.230313mzl4w4u92", team_id: "2BUA8C4S2C"
  process signing_id: "com.apple.mdworker_shared", platform_binary: true
end
