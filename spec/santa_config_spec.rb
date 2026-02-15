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

  describe "file access policy: load" do
    it "loads watch items from an external file" do
      tmpfile = "tmp_test_watch_items.rb"
      File.write(tmpfile, <<~RUBY)
        watch_item "LoadedRule" do
          path "/tmp/loaded", prefix: true
          options do
            rule_type "PathsWithAllowedProcesses"
            allow_read_access false
          end
          process signing_id: "com.test.loaded", team_id: "ABCDEF"
        end
      RUBY

      xml = generate do
        payload "P-UUID" do
          payload_type "com.northpolesec.santa"
          payload_version 1

          file_access_policy do
            version "v1.0"
            load tmpfile
          end
        end
      end

      File.delete(tmpfile)

      expect(xml).to include("<key>LoadedRule</key>")
      expect(xml).to include("<string>/tmp/loaded</string>")
      expect(xml).to include("<string>com.test.loaded</string>")
      expect(xml).to include("<string>ABCDEF</string>")
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

  describe "static_rules with block DSL" do
    it "generates a rule with identifier, rule_type, and policy" do
      xml = generate do
        payload "P-UUID" do
          payload_type "com.northpolesec.santa"
          payload_version 1

          static_rules do
            rule do
              identifier "EQHXZ8M8AV:com.google.Chrome"
              rule_type "SIGNINGID"
              policy "ALLOWLIST"
            end
          end
        end
      end

      expect(xml).to include("<key>StaticRules</key>")
      expect(xml).to include("<key>identifier</key>")
      expect(xml).to include("<string>EQHXZ8M8AV:com.google.Chrome</string>")
      expect(xml).to include("<key>rule_type</key>")
      expect(xml).to include("<string>SIGNINGID</string>")
      expect(xml).to include("<key>policy</key>")
      expect(xml).to include("<string>ALLOWLIST</string>")
    end

    it "generates a CEL rule with cel_expr" do
      xml = generate do
        payload "P-UUID" do
          payload_type "com.northpolesec.santa"
          payload_version 1

          static_rules do
            rule do
              identifier "EQHXZ8M8AV:com.google.Chrome"
              rule_type "SIGNINGID"
              policy "CEL"
              cel_expr "target.signing_time >= timestamp('2025-01-01T00:00:00Z')"
            end
          end
        end
      end

      expect(xml).to include("<key>policy</key>")
      expect(xml).to include("<string>CEL</string>")
      expect(xml).to include("<key>cel_expr</key>")
      expect(xml).to include("<string>target.signing_time &gt;= timestamp('2025-01-01T00:00:00Z')</string>")
    end

    it "supports custom_msg and custom_url" do
      xml = generate do
        payload "P-UUID" do
          payload_type "com.northpolesec.santa"
          payload_version 1

          static_rules do
            rule do
              identifier "EQHXZ8M8AV:com.google.Chrome"
              rule_type "SIGNINGID"
              policy "BLOCKLIST"
              custom_msg "This application is blocked"
              custom_url "https://example.com/help"
            end
          end
        end
      end

      expect(xml).to include("<key>custom_msg</key>")
      expect(xml).to include("<string>This application is blocked</string>")
      expect(xml).to include("<key>custom_url</key>")
      expect(xml).to include("<string>https://example.com/help</string>")
    end

    it "supports comment field" do
      xml = generate do
        payload "P-UUID" do
          payload_type "com.northpolesec.santa"
          payload_version 1

          static_rules do
            rule do
              identifier "platform:com.apple.curl"
              rule_type "SIGNINGID"
              policy "ALLOWLIST"
              comment "Allow curl"
            end
          end
        end
      end

      expect(xml).to include("<key>comment</key>")
      expect(xml).to include("<string>Allow curl</string>")
    end

    it "generates multiple rules" do
      xml = generate do
        payload "P-UUID" do
          payload_type "com.northpolesec.santa"
          payload_version 1

          static_rules do
            rule do
              identifier "EQHXZ8M8AV:com.google.Chrome"
              rule_type "SIGNINGID"
              policy "ALLOWLIST"
            end

            rule do
              identifier "43AQ936H96:org.mozilla.firefox"
              rule_type "SIGNINGID"
              policy "BLOCKLIST"
            end
          end
        end
      end

      expect(xml).to include("<string>EQHXZ8M8AV:com.google.Chrome</string>")
      expect(xml).to include("<string>43AQ936H96:org.mozilla.firefox</string>")
    end

    it "loads rules from an external file" do
      tmpfile = "tmp_test_static_rules.rb"
      File.write(tmpfile, <<~RUBY)
        rule do
          identifier "EQHXZ8M8AV:com.google.Chrome"
          rule_type "SIGNINGID"
          policy "CEL"
          cel_expr "target.signing_time >= timestamp('2025-06-01T00:00:00Z')"
          custom_msg "Chrome is too old"
        end
      RUBY

      xml = generate do
        payload "P-UUID" do
          payload_type "com.northpolesec.santa"
          payload_version 1

          static_rules do
            load tmpfile
          end
        end
      end

      File.delete(tmpfile)

      expect(xml).to include("<key>StaticRules</key>")
      expect(xml).to include("<string>EQHXZ8M8AV:com.google.Chrome</string>")
      expect(xml).to include("<string>Chrome is too old</string>")
    end

    it "still supports raw array for backward compatibility" do
      xml = generate do
        payload "P-UUID" do
          payload_type "com.northpolesec.santa"
          payload_version 1
          static_rules []
        end
      end

      expect(xml).to include("<key>StaticRules</key>")
      expect(xml).to include("<array>")
    end

    it "supports all rule types" do
      xml = generate do
        payload "P-UUID" do
          payload_type "com.northpolesec.santa"
          payload_version 1

          static_rules do
            rule do
              identifier "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
              rule_type "BINARY"
              policy "BLOCKLIST"
            end

            rule do
              identifier "EQHXZ8M8AV"
              rule_type "TEAMID"
              policy "ALLOWLIST"
            end

            rule do
              identifier "ea7c2330699c760b2d6c2c3e703fde01ca54e9b4"
              rule_type "CDHASH"
              policy "SILENT_BLOCKLIST"
            end
          end
        end
      end

      expect(xml).to include("<string>BINARY</string>")
      expect(xml).to include("<string>TEAMID</string>")
      expect(xml).to include("<string>CDHASH</string>")
      expect(xml).to include("<string>SILENT_BLOCKLIST</string>")
    end

    it "supports CEL expressions inspecting args" do
      xml = generate do
        payload "P-UUID" do
          payload_type "com.northpolesec.santa"
          payload_version 1

          static_rules do
            rule do
              identifier "platform:com.apple.spctl"
              rule_type "SIGNINGID"
              policy "CEL"
              cel_expr "'--master-disable' in args ? BLOCKLIST : ALLOWLIST"
              custom_msg "Disabling Gatekeeper is not allowed"
            end
          end
        end
      end

      expect(xml).to include("<key>cel_expr</key>")
      expect(xml).to include("'--master-disable' in args ? BLOCKLIST : ALLOWLIST")
      expect(xml).to include("<string>Disabling Gatekeeper is not allowed</string>")
    end
  end
end
