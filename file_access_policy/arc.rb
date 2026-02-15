# Vibe coded untested config

watch_item "ArcCookies" do
  path "/Users/*/Library/Application Support/Arc/User Data/*/Cookies", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "This file is configured to only be accessed by executable binaries signed by the Arc TeamID S6N382Y83G"
  end

  process signing_id: "company.thebrowser.Browser.helper", team_id: "S6N382Y83G"
  process signing_id: "com.apple.mdworker_shared", platform_binary: true
end

watch_item "ArcLocalStorage" do
  path "/Users/*/Library/Application Support/Arc/User Data/*/Local Storage/leveldb", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "This file is configured to only be accessed by executable binaries signed by the Arc TeamID S6N382Y83G"
  end

  process signing_id: "company.thebrowser.Browser.helper", team_id: "S6N382Y83G"
  process signing_id: "com.apple.mdworker_shared", platform_binary: true
end

watch_item "ArcIndexedDB" do
  path "/Users/*/Library/Application Support/Arc/User Data/*/IndexedDB", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "This file is configured to only be accessed by executable binaries signed by the Arc TeamID S6N382Y83G"
  end

  process signing_id: "company.thebrowser.Browser.helper", team_id: "S6N382Y83G"
  process signing_id: "com.apple.mdworker_shared", platform_binary: true
end

watch_item "ArcWebData" do
  path "/Users/*/Library/Application Support/Arc/User Data/*/databases", prefix: true
  path "/Users/*/Library/Application Support/Arc/User Data/*/Web Data", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "This file is configured to only be accessed by executable binaries signed by the Arc TeamID S6N382Y83G"
  end

  process signing_id: "company.thebrowser.Browser.helper", team_id: "S6N382Y83G"
  process signing_id: "com.apple.mdworker_shared", platform_binary: true
end

watch_item "ArcSessionStorage" do
  path "/Users/*/Library/Application Support/Arc/User Data/*/Session Storage", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "This file is configured to only be accessed by executable binaries signed by the Arc TeamID S6N382Y83G"
  end

  process signing_id: "company.thebrowser.Browser.helper", team_id: "S6N382Y83G"
  process signing_id: "com.apple.mdworker_shared", platform_binary: true
end
