require_relative "lib/santa_config"

SantaConfig.generate("santa.mobileconfig", "AFA02DE3-ACA6-49C4-9980-A3664E22E446") do
  payload_description "Manages Santa's configuration"
  payload_display_name "Santa: Configuration"
  payload_identifier "uk.craigbass.santa"
  payload_organization "Craig Ltd"
  payload_scope "System"
  payload_version 1

  payload "C5E31F41-173D-4804-8F94-0B87FA6FB73E" do
    client_mode 1
    enable_silent_mode false
    static_rules []
    telemetry ["FileAccess"]
    event_log_type "syslog"
    payload_display_name "Santa Configuration"
    payload_identifier "uk.craigbass.santa.3C5E31F41-173D-4804-8F94-0B87FA6FB73E"
    payload_type "com.northpolesec.santa"
    payload_version 1

    file_access_policy do
      version "v1.0"

      watch_item "ChromeCookies" do
        path "/Users/*/Library/Application Support/Google/Chrome/*/Cookies", prefix: true

        options do
          allow_read_access false
          audit_only true
          rule_type "PathsWithAllowedProcesses"
          block_message "This file is configured to only be accessed by executable binaries signed by the Chrome TeamID EQHXZ8M8AV"
        end

        process signing_id: "com.google.Chrome.helper", team_id: "EQHXZ8M8AV"
        process signing_id: "com.apple.mdworker_shared", platform_binary: true
      end

      watch_item "SafariCookies" do
        path "/Users/*/Library/Cookies/Cookies.binarycookies", prefix: false
        path "/Users/*/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies", prefix: false

        options do
          allow_read_access false
          audit_only true
          rule_type "PathsWithAllowedProcesses"
          block_message "This file is configured to only be accessed by Safari"
        end

        process signing_id: "com.apple.Safari", platform_binary: true
        process signing_id: "com.apple.SafariServices", platform_binary: true
        process signing_id: "com.apple.WebKit.Networking", platform_binary: true
        process signing_id: "com.apple.mdworker_shared", platform_binary: true
      end

      watch_item "FirefoxCookies" do
        path "/Users/*/Library/Application Support/Firefox/Profiles/*/cookies.sqlite", prefix: true

        options do
          allow_read_access false
          audit_only true
          rule_type "PathsWithAllowedProcesses"
          block_message "This file is configured to only be accessed by executable binaries signed by the Firefox TeamID 43AQ936H96"
        end

        process signing_id: "org.mozilla.firefox", team_id: "43AQ936H96"
        process signing_id: "com.apple.mdworker_shared", platform_binary: true
      end

      watch_item "EdgeCookies" do
        path "/Users/*/Library/Application Support/Microsoft Edge/*/Cookies", prefix: true

        options do
          allow_read_access false
          audit_only true
          rule_type "PathsWithAllowedProcesses"
          block_message "This file is configured to only be accessed by executable binaries signed by the Edge TeamID UBF8T346G9"
        end

        process signing_id: "com.microsoft.Edge.helper", team_id: "UBF8T346G9"
        process signing_id: "com.apple.mdworker_shared", platform_binary: true
      end

      watch_item "BraveCookies" do
        path "/Users/*/Library/Application Support/BraveSoftware/Brave-Browser/*/Cookies", prefix: true

        options do
          allow_read_access false
          audit_only true
          rule_type "PathsWithAllowedProcesses"
          block_message "This file is configured to only be accessed by executable binaries signed by the Brave TeamID KL8N8XSYF4"
        end

        process signing_id: "com.brave.Browser.helper", team_id: "KL8N8XSYF4"
        process signing_id: "com.apple.mdworker_shared", platform_binary: true
      end

      watch_item "ArcCookies" do
        path "/Users/*/Library/Application Support/Arc/User Data/*/Cookies", prefix: true

        options do
          allow_read_access false
          audit_only true
          rule_type "PathsWithAllowedProcesses"
          block_message "This file is configured to only be accessed by executable binaries signed by the Arc TeamID S6N382Y83G"
        end

        process signing_id: "company.thebrowser.Browser.helper", team_id: "S6N382Y83G"
        process signing_id: "com.apple.mdworker_shared", platform_binary: true
      end
    end
  end
end
