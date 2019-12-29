# A profile for controlling auditing around ATT&CK technique T1079
# URL: https://attack.mitre.org/techniques/T1079/
#
# @param enabled - boolean
class profiles::command_and_control::t1079 (
    $enabled = lookup('profiles::command_and_control::t1079::enabled', Boolean, 'first', true),
) {
  $rules = [
    '-w /usr/sbin/stunnel -p x -k t1079_multilayer_encryption'
  ]

  if $enabled {
    auditd::rule { $rules: }
  }
}
