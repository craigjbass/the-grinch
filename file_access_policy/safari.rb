watch_item "SafariCookies" do
  path "/Users/*/Library/Cookies/Cookies.binarycookies", prefix: false
  path "/Users/*/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies", prefix: false

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "This file is configured to only be accessed by Safari"
  end

  process signing_id: "com.apple.Safari", platform_binary: true
  process signing_id: "com.apple.SafariServices", platform_binary: true
  process signing_id: "com.apple.WebKit.Networking", platform_binary: true
  process signing_id: "com.apple.mdworker_shared", platform_binary: true
end

watch_item "SafariLocalStorage" do
  path "/Users/*/Library/Safari/LocalStorage", prefix: true
  path "/Users/*/Library/Containers/com.apple.Safari/Data/Library/WebKit/WebsiteData/LocalStorage", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "This file is configured to only be accessed by Safari"
  end

  process signing_id: "com.apple.Safari", platform_binary: true
  process signing_id: "com.apple.SafariServices", platform_binary: true
  process signing_id: "com.apple.WebKit.WebContent", platform_binary: true
  process signing_id: "com.apple.mdworker_shared", platform_binary: true
  process signing_id: "com.apple.WebKit.Networking", platform_binary: true
end

watch_item "SafariIndexedDB" do
  path "/Users/*/Library/Safari/Databases/IndexedDB", prefix: true
  path "/Users/*/Library/Containers/com.apple.Safari/Data/Library/WebKit/WebsiteData/IndexedDB", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "This file is configured to only be accessed by Safari"
  end

  process signing_id: "com.apple.Safari", platform_binary: true
  process signing_id: "com.apple.SafariServices", platform_binary: true
  process signing_id: "com.apple.WebKit.WebContent", platform_binary: true
  process signing_id: "com.apple.mdworker_shared", platform_binary: true
end

watch_item "SafariWebData" do
  path "/Users/*/Library/Safari/Databases", prefix: true
  path "/Users/*/Library/Containers/com.apple.Safari/Data/Library/WebKit/WebsiteData/WebSQL", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "This file is configured to only be accessed by Safari"
  end

  process signing_id: "com.apple.Safari", platform_binary: true
  process signing_id: "com.apple.finder", platform_binary: true
  process signing_id: "com.apple.SafariServices", platform_binary: true
  process signing_id: "com.apple.WebKit.WebContent", platform_binary: true
  process signing_id: "com.apple.mdworker_shared", platform_binary: true
  process signing_id: "com.apple.WebKit.Networking", platform_binary: true
end
