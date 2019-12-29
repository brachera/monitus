# A profile for controlling auditing around ATT&CK technique T1108
# URL: https://attack.mitre.org/techniques/T1108/
#
# @param enabled - boolean
class profiles::persistence::t1108 (
  $enabled = lookup('profiles::persistence::t1108::enabled', Boolean, 'first', false),
){
  $rules = [
    '-w /var/run/utmp -p wa -k t1108_redundant_access',
    '-w /var/log/wtmp -p wa -k t1108_redundant_access',
    '-w /var/log/btmp -p wa -k t1108_redundant_access'
  ]

  if $enabled {
    auditd::rule { $rules: }
  }
}
