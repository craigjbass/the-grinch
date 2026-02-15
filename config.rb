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
    static_rules do
      load "static_rules/gatekeeper.rb"
    end
    telemetry ["FileAccess", "Execution", "Allowlist", "GatekeeperOverride", "TCCModification", "XProtect"]
    entitlements_team_id_filter ["platform"]
    entitlements_prefix_filter ["com.apple.private"]
    event_log_type "syslog"
    payload_display_name "Santa Configuration"
    payload_identifier "uk.craigbass.santa.3C5E31F41-173D-4804-8F94-0B87FA6FB73E"
    payload_type "com.northpolesec.santa"
    payload_version 1

    file_access_policy do
      version "v1.0"
      load "file_access_policy/chrome.rb"
      load "file_access_policy/safari.rb"
      load "file_access_policy/firefox.rb"
      load "file_access_policy/edge.rb"
      load "file_access_policy/brave.rb"
      load "file_access_policy/arc.rb"
      load "file_access_policy/imessage.rb"
      load "file_access_policy/ssh_keys.rb"
      load "file_access_policy/pam.rb"
      load "file_access_policy/password_hashes.rb"
      load "file_access_policy/launch_items.rb"
      load "file_access_policy/scheduled_tasks.rb"
      load "file_access_policy/keychain.rb"
      load "file_access_policy/1password.rb"
      load "file_access_policy/docker.rb"
      load "file_access_policy/ai_tools.rb"
      load "file_access_policy/spotlight.rb"
      load "file_access_policy/audio_plugins.rb"
      load "file_access_policy/in_memory_loading.rb"
      load "file_access_policy/electron_apps.rb"
    end
  end
end
