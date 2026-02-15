# Vibe coded untested config

watch_item "EdgeCookies" do
  path "/Users/*/Library/Application Support/Microsoft Edge/*/Cookies", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "This file is configured to only be accessed by executable binaries signed by the Edge TeamID UBF8T346G9"
  end

  process signing_id: "com.microsoft.Edge.helper", team_id: "UBF8T346G9"
  process signing_id: "com.apple.mdworker_shared", platform_binary: true
end

watch_item "EdgeLocalStorage" do
  path "/Users/*/Library/Application Support/Microsoft Edge/*/Local Storage/leveldb", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "This file is configured to only be accessed by executable binaries signed by the Edge TeamID UBF8T346G9"
  end

  process signing_id: "com.microsoft.Edge.helper", team_id: "UBF8T346G9"
  process signing_id: "com.apple.mdworker_shared", platform_binary: true
end

watch_item "EdgeIndexedDB" do
  path "/Users/*/Library/Application Support/Microsoft Edge/*/IndexedDB", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "This file is configured to only be accessed by executable binaries signed by the Edge TeamID UBF8T346G9"
  end

  process signing_id: "com.microsoft.Edge.helper", team_id: "UBF8T346G9"
  process signing_id: "com.apple.mdworker_shared", platform_binary: true
end

watch_item "EdgeWebData" do
  path "/Users/*/Library/Application Support/Microsoft Edge/*/databases", prefix: true
  path "/Users/*/Library/Application Support/Microsoft Edge/*/Web Data", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "This file is configured to only be accessed by executable binaries signed by the Edge TeamID UBF8T346G9"
  end

  process signing_id: "com.microsoft.Edge.helper", team_id: "UBF8T346G9"
  process signing_id: "com.apple.mdworker_shared", platform_binary: true
end

watch_item "EdgeSessionStorage" do
  path "/Users/*/Library/Application Support/Microsoft Edge/*/Session Storage", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "This file is configured to only be accessed by executable binaries signed by the Edge TeamID UBF8T346G9"
  end

  process signing_id: "com.microsoft.Edge.helper", team_id: "UBF8T346G9"
  process signing_id: "com.apple.mdworker_shared", platform_binary: true
end
