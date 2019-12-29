# A profile for controlling auditing around ATT&CK technique t1014
# URL: https://attack.mitre.org/techniques/t1014/
#
# @param enabled - boolean
class profiles::defense_evasion::t1014 (
  $enabled = lookup('profiles::defense_evasion::t1014::enabled', Boolean, 'first', false),
){
  $rules = [
    '-a always,exit -F arch=b64 -S kexec_load -k 	t1014_rootkit',
    '-a always,exit -F arch=b32 -S sys_kexec_load -k t1014_rootkit'
  ]

  if $enabled {
    auditd::rule { $rules: }
  }
}
