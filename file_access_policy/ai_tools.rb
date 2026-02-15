watch_item "AWSCredentials" do
  path "/Users/*/.aws/credentials", prefix: false
  path "/Users/*/.aws/config", prefix: false

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "AWS credential files are protected from unauthorized access"
  end

  process signing_id: "com.amazon.aws.cli2", team_id: "94KV3E626L"
  process signing_id: "com.apple.Terminal", platform_binary: true
end

watch_item "GnuPGKeys" do
  path "/Users/*/.gnupg/", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "GnuPG keys are protected from unauthorized access"
  end

  process signing_id: "com.apple.Terminal", platform_binary: true
end

watch_item "GitHubCLICredentials" do
  path "/Users/*/.config/gh/", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "GitHub CLI credentials are protected from unauthorized access"
  end

  process signing_id: "com.apple.Terminal", platform_binary: true
end

watch_item "NpmCredentials" do
  path "/Users/*/.npmrc", prefix: false

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "npm credentials are protected from unauthorized access"
  end

  process signing_id: "com.apple.Terminal", platform_binary: true
end

watch_item "PyPICredentials" do
  path "/Users/*/.pypirc", prefix: false

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "PyPI credentials are protected from unauthorized access"
  end

  process signing_id: "com.apple.Terminal", platform_binary: true
end
