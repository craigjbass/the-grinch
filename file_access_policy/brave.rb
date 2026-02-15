# Vibe coded untested config

watch_item "BraveCookies" do
  path "/Users/*/Library/Application Support/BraveSoftware/Brave-Browser/*/Cookies", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "This file is configured to only be accessed by executable binaries signed by the Brave TeamID KL8N8XSYF4"
  end

  process signing_id: "com.brave.Browser.helper", team_id: "KL8N8XSYF4"
  process signing_id: "com.apple.mdworker_shared", platform_binary: true
end

watch_item "BraveLocalStorage" do
  path "/Users/*/Library/Application Support/BraveSoftware/Brave-Browser/*/Local Storage/leveldb", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "This file is configured to only be accessed by executable binaries signed by the Brave TeamID KL8N8XSYF4"
  end

  process signing_id: "com.brave.Browser.helper", team_id: "KL8N8XSYF4"
  process signing_id: "com.apple.mdworker_shared", platform_binary: true
end

watch_item "BraveIndexedDB" do
  path "/Users/*/Library/Application Support/BraveSoftware/Brave-Browser/*/IndexedDB", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "This file is configured to only be accessed by executable binaries signed by the Brave TeamID KL8N8XSYF4"
  end

  process signing_id: "com.brave.Browser.helper", team_id: "KL8N8XSYF4"
  process signing_id: "com.apple.mdworker_shared", platform_binary: true
end

watch_item "BraveWebData" do
  path "/Users/*/Library/Application Support/BraveSoftware/Brave-Browser/*/databases", prefix: true
  path "/Users/*/Library/Application Support/BraveSoftware/Brave-Browser/*/Web Data", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "This file is configured to only be accessed by executable binaries signed by the Brave TeamID KL8N8XSYF4"
  end

  process signing_id: "com.brave.Browser.helper", team_id: "KL8N8XSYF4"
  process signing_id: "com.apple.mdworker_shared", platform_binary: true
end

watch_item "BraveSessionStorage" do
  path "/Users/*/Library/Application Support/BraveSoftware/Brave-Browser/*/Session Storage", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "This file is configured to only be accessed by executable binaries signed by the Brave TeamID KL8N8XSYF4"
  end

  process signing_id: "com.brave.Browser.helper", team_id: "KL8N8XSYF4"
  process signing_id: "com.apple.mdworker_shared", platform_binary: true
end
