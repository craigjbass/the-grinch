watch_item "DockerConfig" do
  path "/Users/*/Library/Group Containers/group.com.docker/", prefix: true
  path "/Users/*/.docker/", prefix: true

  options do
    allow_read_access false
    audit_only false
    rule_type "PathsWithAllowedProcesses"
    block_message "Docker configuration is protected from unauthorized access"
  end

  process signing_id: "com.docker.docker", team_id: "9BNSXJN65R"
  process signing_id: "com.docker.helper", team_id: "9BNSXJN65R"
  process signing_id: "com.apple.mdworker_shared", platform_binary: true
end
