watch_item "ChromeCookies" do
  path "/Users/*/Library/Application Support/Google/Chrome/*/Cookies", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "This file is configured to only be accessed by executable binaries signed by the Chrome TeamID EQHXZ8M8AV"
  end

  process signing_id: "com.google.Chrome", team_id: "EQHXZ8M8AV"
  process signing_id: "com.google.Chrome.helper", team_id: "EQHXZ8M8AV"
  process signing_id: "com.apple.mdworker_shared", platform_binary: true
end

watch_item "ChromeLocalStorage" do
  path "/Users/*/Library/Application Support/Google/Chrome/*/Local Storage/leveldb", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "This file is configured to only be accessed by executable binaries signed by the Chrome TeamID EQHXZ8M8AV"
  end

  process signing_id: "com.google.Chrome", team_id: "EQHXZ8M8AV"
  process signing_id: "com.google.Chrome.helper", team_id: "EQHXZ8M8AV"
  process signing_id: "com.apple.mdworker_shared", platform_binary: true
end

watch_item "ChromeIndexedDB" do
  path "/Users/*/Library/Application Support/Google/Chrome/*/IndexedDB", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "This file is configured to only be accessed by executable binaries signed by the Chrome TeamID EQHXZ8M8AV"
  end

  process signing_id: "com.google.Chrome", team_id: "EQHXZ8M8AV"
  process signing_id: "com.google.Chrome.helper", team_id: "EQHXZ8M8AV"
  process signing_id: "com.apple.mdworker_shared", platform_binary: true
end

watch_item "ChromeWebData" do
  path "/Users/*/Library/Application Support/Google/Chrome/*/databases", prefix: true
  path "/Users/*/Library/Application Support/Google/Chrome/*/Web Data", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "This file is configured to only be accessed by executable binaries signed by the Chrome TeamID EQHXZ8M8AV"
  end

  process signing_id: "com.google.Chrome", team_id: "EQHXZ8M8AV"
  process signing_id: "com.google.Chrome.helper", team_id: "EQHXZ8M8AV"
  process signing_id: "com.apple.mdworker_shared", platform_binary: true
end

watch_item "ChromeSessionStorage" do
  path "/Users/*/Library/Application Support/Google/Chrome/*/Session Storage", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "This file is configured to only be accessed by executable binaries signed by the Chrome TeamID EQHXZ8M8AV"
  end

  process signing_id: "com.google.Chrome", team_id: "EQHXZ8M8AV"
  process signing_id: "com.google.Chrome.helper", team_id: "EQHXZ8M8AV"
  process signing_id: "com.apple.mdworker_shared", platform_binary: true
end
