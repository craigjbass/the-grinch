# Vibe coded untested config

watch_item "FirefoxCookies" do
  path "/Users/*/Library/Application Support/Firefox/Profiles/*/cookies.sqlite", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "This file is configured to only be accessed by executable binaries signed by the Firefox TeamID 43AQ936H96"
  end

  process signing_id: "org.mozilla.firefox", team_id: "43AQ936H96"
  process signing_id: "com.apple.mdworker_shared", platform_binary: true
end

watch_item "FirefoxLocalStorage" do
  path "/Users/*/Library/Application Support/Firefox/Profiles/*/storage/default", prefix: true
  path "/Users/*/Library/Application Support/Firefox/Profiles/*/webappsstore.sqlite", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "This file is configured to only be accessed by executable binaries signed by the Firefox TeamID 43AQ936H96"
  end

  process signing_id: "org.mozilla.firefox", team_id: "43AQ936H96"
  process signing_id: "com.apple.mdworker_shared", platform_binary: true
end

watch_item "FirefoxIndexedDB" do
  path "/Users/*/Library/Application Support/Firefox/Profiles/*/storage/default/*/idb", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "This file is configured to only be accessed by executable binaries signed by the Firefox TeamID 43AQ936H96"
  end

  process signing_id: "org.mozilla.firefox", team_id: "43AQ936H96"
  process signing_id: "com.apple.mdworker_shared", platform_binary: true
end
