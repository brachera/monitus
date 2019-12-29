# A profile for controlling auditing around ATT&CK technique t1052
# URL: https://attack.mitre.org/techniques/T1052/
#
# @param enabled - boolean
class profiles::exfiltration::t1052 (
    $enabled = lookup('profiles::exfiltration::t1052::enabled', Boolean, 'first', false),
) {
  $rules = [
    '-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k t1052_exfiltration_over_physical_medium',
    '-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k t1052_exfiltration_over_physical_medium'
  ]

  if $enabled {
    auditd::rule { $rules: }
  }
}
