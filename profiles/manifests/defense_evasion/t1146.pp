# A profile for controlling auditing around ATT&CK technique T1146
# URL: https://attack.mitre.org/techniques/T1146/
#
# @param enabled - boolean
class profiles::defense_evasion::t1146 (
  $enabled = lookup('profiles::defense_evasion::t1146::enabled', Boolean, 'first', false),
){
  if $enabled {
    $::bash_histories.split('\n').each |String $bash_history| {
      auditd::rule { "-a always,exit -F arch=b64 -S rename,rmdir,unlink,unlinkat,renameat -F dir=${bash_history} \
-k t1146_clear_command_history": }
    }
  }
}
