# A profile for controlling auditing around ATT&CK tecnique T1057
# URL: https://attack.mitre.org/techniques/T1057/
#
# @param enabled - boolean
class profiles::discovery::t1057 (
  $enabled = lookup('profiles::discovery::t1057::enabled', Boolean, 'first', false),
){
  $rules = [
    '-w /usr/bin/ps -p x -k t1057_process_discovery'
  ]

  if $enabled {
    auditd::rule { $rules: }
  }
}
