require_relative "../lib/santa_config"

RSpec.describe SantaConfig do
  let(:output_path) { "tmp_test.mobileconfig" }

  after { File.delete(output_path) if File.exist?(output_path) }

  def generate(&block)
    SantaConfig.generate(output_path, "TEST-UUID-1234", &block)
    File.read(output_path)
  end

  describe "profile level" do
    it "generates valid plist wrapping" do
      xml = generate { payload_version 1 }

      expect(xml).to include('<?xml version="1.0" encoding="UTF-8"?>')
      expect(xml).to include('<plist version="1.0">')
      expect(xml).to include("</plist>")
    end

    it "anchors the profile on its UUID" do
      xml = generate { payload_version 1 }

      expect(xml).to include("<key>PayloadUUID</key>")
      expect(xml).to include("<string>TEST-UUID-1234</string>")
    end

    it "includes all profile metadata" do
      xml = generate do
        payload_description "Test Description"
        payload_display_name "Test Display"
        payload_identifier "com.test"
        payload_organization "Test Org"
        payload_scope "System"
        payload_version 1
      end

      expect(xml).to include("<string>Test Description</string>")
      expect(xml).to include("<string>Test Display</string>")
      expect(xml).to include("<string>com.test</string>")
      expect(xml).to include("<string>Test Org</string>")
      expect(xml).to include("<string>System</string>")
      expect(xml).to include("<string>Configuration</string>")
      expect(xml).to include("<integer>1</integer>")
    end
  end

  describe "payload level" do
    it "anchors payloads on their UUID" do
      xml = generate do
        payload "PAYLOAD-UUID-5678" do
          payload_type "com.northpolesec.santa"
          payload_version 1
        end
      end

      expect(xml).to include("<string>PAYLOAD-UUID-5678</string>")
    end

    it "includes santa configuration fields" do
      xml = generate do
        payload "PAYLOAD-UUID" do
          client_mode 2
          enable_silent_mode true
          static_rules []
          telemetry ["FileAccess"]
          event_log_type "syslog"
          payload_display_name "Santa"
          payload_identifier "com.test.santa"
          payload_type "com.northpolesec.santa"
          payload_version 1
        end
      end

      expect(xml).to include("<integer>2</integer>")
      expect(xml).to include("<true/>")
      expect(xml).to include("<string>FileAccess</string>")
      expect(xml).to include("<string>syslog</string>")
    end
  end

  describe "file access policy" do
    it "includes version and watch items" do
      xml = generate do
        payload "P-UUID" do
          payload_type "com.northpolesec.santa"
          payload_version 1

          file_access_policy do
            version "v2.0"

            watch_item "TestRule" do
              path "/tmp/test", prefix: true

              options do
                rule_type "PathsWithAllowedProcesses"
                allow_read_access false
                audit_only false
                block_message "Blocked!"
              end

              process signing_id: "com.test.app", team_id: "TEAM123"
            end
          end
        end
      end

      expect(xml).to include("<string>v2.0</string>")
      expect(xml).to include("<key>TestRule</key>")
      expect(xml).to include("<string>/tmp/test</string>")
      expect(xml).to include("<string>com.test.app</string>")
      expect(xml).to include("<string>TEAM123</string>")
      expect(xml).to include("<string>Blocked!</string>")
    end

    it "supports platform_binary on processes" do
      xml = generate do
        payload "P-UUID" do
          payload_type "com.northpolesec.santa"
          payload_version 1

          file_access_policy do
            version "v1.0"

            watch_item "Rule" do
              path "/test"
              options { rule_type "PathsWithAllowedProcesses" }
              process signing_id: "com.apple.test", platform_binary: true
            end
          end
        end
      end

      expect(xml).to include("<key>PlatformBinary</key>")
      expect(xml).to include("<true/>")
    end
  end

  # --- NEW FIELDS: Red phase starts here ---

  describe "file access policy: event_detail_url" do
    it "includes EventDetailURL at the policy level" do
      xml = generate do
        payload "P-UUID" do
          payload_type "com.northpolesec.santa"
          payload_version 1

          file_access_policy do
            version "v1.0"
            event_detail_url "https://example.com/events?rule=%rule_name%"
          end
        end
      end

      expect(xml).to include("<key>EventDetailURL</key>")
      expect(xml).to include("<string>https://example.com/events?rule=%rule_name%</string>")
    end
  end

  describe "file access policy: event_detail_text" do
    it "includes EventDetailText at the policy level" do
      xml = generate do
        payload "P-UUID" do
          payload_type "com.northpolesec.santa"
          payload_version 1

          file_access_policy do
            version "v1.0"
            event_detail_text "View Details"
          end
        end
      end

      expect(xml).to include("<key>EventDetailText</key>")
      expect(xml).to include("<string>View Details</string>")
    end
  end

  describe "process: cd_hash" do
    it "includes CDHash in process entries" do
      xml = generate do
        payload "P-UUID" do
          payload_type "com.northpolesec.santa"
          payload_version 1

          file_access_policy do
            version "v1.0"
            watch_item "Rule" do
              path "/test"
              options { rule_type "PathsWithAllowedProcesses" }
              process cd_hash: "abc123def456"
            end
          end
        end
      end

      expect(xml).to include("<key>CDHash</key>")
      expect(xml).to include("<string>abc123def456</string>")
    end
  end

  describe "process: certificate_sha256" do
    it "includes CertificateSha256 in process entries" do
      xml = generate do
        payload "P-UUID" do
          payload_type "com.northpolesec.santa"
          payload_version 1

          file_access_policy do
            version "v1.0"
            watch_item "Rule" do
              path "/test"
              options { rule_type "PathsWithAllowedProcesses" }
              process certificate_sha256: "sha256hashvalue"
            end
          end
        end
      end

      expect(xml).to include("<key>CertificateSha256</key>")
      expect(xml).to include("<string>sha256hashvalue</string>")
    end
  end

  describe "process: binary_path" do
    it "includes BinaryPath in process entries" do
      xml = generate do
        payload "P-UUID" do
          payload_type "com.northpolesec.santa"
          payload_version 1

          file_access_policy do
            version "v1.0"
            watch_item "Rule" do
              path "/test"
              options { rule_type "PathsWithAllowedProcesses" }
              process binary_path: "/usr/local/bin/myapp"
            end
          end
        end
      end

      expect(xml).to include("<key>BinaryPath</key>")
      expect(xml).to include("<string>/usr/local/bin/myapp</string>")
    end
  end

  describe "options: event_detail_url" do
    it "includes EventDetailURL in watch item options" do
      xml = generate do
        payload "P-UUID" do
          payload_type "com.northpolesec.santa"
          payload_version 1

          file_access_policy do
            version "v1.0"
            watch_item "Rule" do
              path "/test"
              options do
                rule_type "PathsWithAllowedProcesses"
                event_detail_url "https://example.com/rule?path=%accessed_path%"
              end
            end
          end
        end
      end

      expect(xml).to include("<key>EventDetailURL</key>")
      expect(xml).to include("<string>https://example.com/rule?path=%accessed_path%</string>")
    end
  end

  describe "options: event_detail_text" do
    it "includes EventDetailText in watch item options" do
      xml = generate do
        payload "P-UUID" do
          payload_type "com.northpolesec.santa"
          payload_version 1

          file_access_policy do
            version "v1.0"
            watch_item "Rule" do
              path "/test"
              options do
                rule_type "PathsWithAllowedProcesses"
                event_detail_text "Learn More"
              end
            end
          end
        end
      end

      expect(xml).to include("<key>EventDetailText</key>")
      expect(xml).to include("<string>Learn More</string>")
    end
  end

  describe "options: enable_silent_mode" do
    it "includes EnableSilentMode in watch item options" do
      xml = generate do
        payload "P-UUID" do
          payload_type "com.northpolesec.santa"
          payload_version 1

          file_access_policy do
            version "v1.0"
            watch_item "Rule" do
              path "/test"
              options do
                rule_type "PathsWithAllowedProcesses"
                enable_silent_mode true
              end
            end
          end
        end
      end

      expect(xml).to include("<key>EnableSilentMode</key>")
      expect(xml).to include("<true/>")
    end
  end

  describe "options: enable_silent_tty_mode" do
    it "includes EnableSilentTTYMode in watch item options" do
      xml = generate do
        payload "P-UUID" do
          payload_type "com.northpolesec.santa"
          payload_version 1

          file_access_policy do
            version "v1.0"
            watch_item "Rule" do
              path "/test"
              options do
                rule_type "PathsWithAllowedProcesses"
                enable_silent_tty_mode true
              end
            end
          end
        end
      end

      expect(xml).to include("<key>EnableSilentTTYMode</key>")
      expect(xml).to include("<true/>")
    end
  end
end
