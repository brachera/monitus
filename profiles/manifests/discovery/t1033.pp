# A profile for controlling auditing around ATT&CK tecnique T1033
# URL: https://attack.mitre.org/techniques/T1033/
#
# @param enabled - boolean
class profiles::discovery::t1033 (
  $enabled = lookup('profiles::discovery::t1033::enabled', Boolean, 'first', false),
){
  $rules = [
    '-w /usr/bin/w -p x -k t1033_system_owner_user_discovery',
    '-w /usr/bin/who -p x -k t1033_system_owner_user_discovery',
    '-w /usr/bin/whoami -p x -k t1033_system_owner_user_discovery',
  ]

  if $enabled {
    auditd::rule { $rules: }
  }
}
