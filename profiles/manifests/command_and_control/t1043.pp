# A profile for controlling auditing around ATT&CK technique T1043
# URL: https://attack.mitre.org/techniques/T1043/
#
# @param enabled - boolean
class profiles::command_and_control::t1043 (
  $enabled = lookup('profiles::command_and_control::t1043::enabled', Boolean, 'first', false),
){
  $rules = [
    '-a exit,always -F arch=b64 -S connect -F a2!=110 -k t1043_commonly_used_port',
    '-a exit,always -F arch=b32 -S socketcall -F a0=3 -k t1043_commonly_used_port'
  ]

  if $enabled {
    auditd::rule { $rules: }
  }
}
