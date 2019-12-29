# A profile for controlling auditing around ATT&CK technique T1068
# URL: https://attack.mitre.org/techniques/T1068/
#
# @param enabled - boolean
class profiles::privilege_escalation::t1068 (
  $enabled = lookup('profiles::privilege_escalation::t1068::enabled', Boolean, 'first', false),
){
  $rules = [
    '-a exit,always -F arch=b64 -S open -F dir=/etc -F success=0 -k t1068_exploitation_for_privilege_escalation',
    '-a exit,always -F arch=b64 -S open -F dir=/bin -F success=0 -k t1068_exploitation_for_privilege_escalation',
    '-a exit,always -F arch=b64 -S open -F dir=/sbin -F success=0 -k t1068_exploitation_for_privilege_escalation',
    '-a exit,always -F arch=b64 -S open -F dir=/usr/bin -F success=0 -k t1068_exploitation_for_privilege_escalation',
    '-a exit,always -F arch=b64 -S open -F dir=/usr/sbin -F success=0 -k t1068_exploitation_for_privilege_escalation',
    '-a exit,always -F arch=b64 -S open -F dir=/var -F success=0 -k t1068_exploitation_for_privilege_escalation',
    '-a exit,always -F arch=b64 -S open -F dir=/home -F success=0 -k t1068_exploitation_for_privilege_escalation',
    '-a exit,always -F arch=b64 -S open -F dir=/srv -F success=0 -k t1068_exploitation_for_privilege_escalation'
  ]

  if $enabled {
    auditd::rule { $rules: }
  }
}
