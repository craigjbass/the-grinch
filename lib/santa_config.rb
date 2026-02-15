module SantaConfig
  def self.generate(output_path, profile_uuid, &block)
    profile = Profile.new(profile_uuid)
    profile.instance_eval(&block)
    xml = PlistWriter.generate(profile.to_plist)
    File.write(output_path, xml)
  end

  class Profile
    def initialize(uuid)
      @uuid = uuid
      @data = {}
      @payloads = []
    end

    def payload_description(val) = @data[:payload_description] = val
    def payload_display_name(val) = @data[:payload_display_name] = val
    def payload_identifier(val) = @data[:payload_identifier] = val
    def payload_organization(val) = @data[:payload_organization] = val
    def payload_scope(val) = @data[:payload_scope] = val
    def payload_version(val) = @data[:payload_version] = val

    def payload(uuid, &block)
      p = Payload.new(uuid)
      p.instance_eval(&block)
      @payloads << p
    end

    def to_plist
      {
        "PayloadContent" => @payloads.map(&:to_plist),
        "PayloadDescription" => @data[:payload_description],
        "PayloadDisplayName" => @data[:payload_display_name],
        "PayloadIdentifier" => @data[:payload_identifier],
        "PayloadOrganization" => @data[:payload_organization],
        "PayloadScope" => @data[:payload_scope],
        "PayloadType" => "Configuration",
        "PayloadUUID" => @uuid,
        "PayloadVersion" => @data[:payload_version],
      }
    end
  end

  class Payload
    def initialize(uuid)
      @uuid = uuid
      @data = {}
      @file_access_policy = nil
    end

    def client_mode(val) = @data[:client_mode] = val
    def enable_silent_mode(val) = @data[:enable_silent_mode] = val
    def static_rules(val) = @data[:static_rules] = val
    def telemetry(val) = @data[:telemetry] = val
    def event_log_type(val) = @data[:event_log_type] = val
    def payload_display_name(val) = @data[:payload_display_name] = val
    def payload_identifier(val) = @data[:payload_identifier] = val
    def payload_type(val) = @data[:payload_type] = val
    def payload_version(val) = @data[:payload_version] = val

    def file_access_policy(&block)
      @file_access_policy = FileAccessPolicy.new
      @file_access_policy.instance_eval(&block)
    end

    def to_plist
      result = {}
      result["ClientMode"] = @data[:client_mode] if @data.key?(:client_mode)
      result["EnableSilentMode"] = @data[:enable_silent_mode] if @data.key?(:enable_silent_mode)
      result["StaticRules"] = @data[:static_rules] if @data.key?(:static_rules)
      result["Telemetry"] = @data[:telemetry] if @data.key?(:telemetry)
      result["EventLogType"] = @data[:event_log_type] if @data.key?(:event_log_type)
      result["FileAccessPolicy"] = @file_access_policy.to_plist if @file_access_policy
      result["PayloadUUID"] = @uuid
      result["PayloadDisplayName"] = @data[:payload_display_name]
      result["PayloadIdentifier"] = @data[:payload_identifier]
      result["PayloadType"] = @data[:payload_type]
      result["PayloadVersion"] = @data[:payload_version]
      result
    end
  end

  class FileAccessPolicy
    def initialize
      @version = nil
      @event_detail_url = nil
      @event_detail_text = nil
      @watch_items = {}
    end

    def version(val) = @version = val
    def event_detail_url(val) = @event_detail_url = val
    def event_detail_text(val) = @event_detail_text = val

    def load(path)
      instance_eval(File.read(path), path)
    end

    def watch_item(name, &block)
      item = WatchItem.new
      item.instance_eval(&block)
      @watch_items[name] = item
    end

    def to_plist
      result = {}
      result["Version"] = @version
      result["EventDetailURL"] = @event_detail_url if @event_detail_url
      result["EventDetailText"] = @event_detail_text if @event_detail_text
      result["WatchItems"] = @watch_items.transform_values(&:to_plist) unless @watch_items.empty?
      result
    end
  end

  class WatchItem
    def initialize
      @paths = []
      @options = nil
      @processes = []
    end

    def path(val, prefix: false)
      @paths << {"Path" => val, "IsPrefix" => prefix}
    end

    def options(&block)
      @options = WatchItemOptions.new
      @options.instance_eval(&block)
    end

    def process(**kwargs)
      p = {}
      p["SigningID"] = kwargs[:signing_id] if kwargs[:signing_id]
      p["TeamID"] = kwargs[:team_id] if kwargs[:team_id]
      p["PlatformBinary"] = kwargs[:platform_binary] if kwargs.key?(:platform_binary)
      p["CDHash"] = kwargs[:cd_hash] if kwargs[:cd_hash]
      p["CertificateSha256"] = kwargs[:certificate_sha256] if kwargs[:certificate_sha256]
      p["BinaryPath"] = kwargs[:binary_path] if kwargs[:binary_path]
      @processes << p
    end

    def to_plist
      result = {}
      result["Paths"] = @paths
      result["Options"] = @options.to_plist if @options
      result["Processes"] = @processes unless @processes.empty?
      result
    end
  end

  class WatchItemOptions
    def initialize
      @data = {}
    end

    def allow_read_access(val) = @data["AllowReadAccess"] = val
    def audit_only(val) = @data["AuditOnly"] = val
    def rule_type(val) = @data["RuleType"] = val
    def block_message(val) = @data["BlockMessage"] = val
    def event_detail_url(val) = @data["EventDetailURL"] = val
    def event_detail_text(val) = @data["EventDetailText"] = val
    def enable_silent_mode(val) = @data["EnableSilentMode"] = val
    def enable_silent_tty_mode(val) = @data["EnableSilentTTYMode"] = val

    def to_plist
      @data
    end
  end

  class PlistWriter
    def self.generate(data)
      xml = +""
      xml << %(<?xml version="1.0" encoding="UTF-8"?>\n)
      xml << %(<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n)
      xml << %(<plist version="1.0">\n)
      write_value(xml, data, 0)
      xml << %(</plist>\n)
      xml
    end

    private

    def self.write_value(xml, value, indent)
      tabs = "\t" * indent
      case value
      when Hash
        xml << "#{tabs}<dict>\n"
        value.each do |k, v|
          xml << "#{tabs}\t<key>#{escape(k)}</key>\n"
          write_value(xml, v, indent + 1)
        end
        xml << "#{tabs}</dict>\n"
      when Array
        xml << "#{tabs}<array>\n"
        value.each { |v| write_value(xml, v, indent + 1) }
        xml << "#{tabs}</array>\n"
      when String
        xml << "#{tabs}<string>#{escape(value)}</string>\n"
      when Integer
        xml << "#{tabs}<integer>#{value}</integer>\n"
      when true
        xml << "#{tabs}<true/>\n"
      when false
        xml << "#{tabs}<false/>\n"
      end
    end

    def self.escape(str)
      str.to_s
        .gsub("&", "&amp;")
        .gsub("<", "&lt;")
        .gsub(">", "&gt;")
    end
  end
end
