rule do
  identifier "platform:com.apple.spctl"
  rule_type "SIGNINGID"
  policy "CEL"
  cel_expr "'--master-disable' in args || '--global-disable' in args || '--disable' in args ? BLOCKLIST : ALLOWLIST"
  custom_msg "Modifying Gatekeeper settings is not allowed"
end
