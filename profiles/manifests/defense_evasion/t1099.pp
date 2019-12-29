# A profile for controlling auditing around ATT&CK technique T1099
# URL: https://attack.mitre.org/techniques/T1099/
#
# @param enabled - boolean
class profiles::defense_evasion::t1099 (
    $enabled = lookup('profiles::defense_evasion::t1099::enabled', Boolean, 'first', false),
) {
  $rules = [
    '-a exit,always -F arch=b32 -S adjtimex -S settimeofday -S clock_settime -k t1099_timestomp',
    '-a exit,always -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k t1099_timestomp',
    '-a always,exit -F arch=b32 -S clock_settime -k t1099_timestomp',
    '-a always,exit -F arch=b64 -S clock_settime -k t1099_timestomp',
    '-w /etc/localtime -p wa -k t1099_timestomp',
    '-a always,exit -F arch=b32 -S utimes -k t1099_timestomp',
    '-a always,exit -F arch=b64 -S utimes -k t1099_timestomp',
    '-a always,exit -F arch=b32 -S utimensat -k t1099_timestomp',
    '-a always,exit -F arch=b64 -S utimensat -k t1099_timestomp'
  ]

  if $enabled {
    auditd::rule { $rules: }
  }
}
