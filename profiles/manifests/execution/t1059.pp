# A profile for controlling auditing around ATT&CK technique T1059
# URL: https://attack.mitre.org/techniques/T1059/
#
# This profile will generate a large amount of logs as it covers
# the execution of all commands on a system. Use sparingly 
#
# @param enabled - boolean
class profiles::execution::t1059 (
  $enabled = lookup('profiles::execution::t1059::enabled', Boolean, 'first', false),
){
  $rules = [
    '-a exit,always -F arch=b64 -S execve -k t1059_command-line_interface',
    '-a exit,always -F arch=b32 -S execve -k t1059_command-line_interface'
  ]

  if $enabled {
    auditd::rule { $rules: }
  }
}
