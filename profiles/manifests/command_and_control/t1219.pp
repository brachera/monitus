# A profile for controlling auditing around ATT&CK technique T1219
# URL: https://attack.mitre.org/techniques/T1219/
#
# @param enabled - boolean
class profiles::command_and_control::t1219 (
  $enabled = lookup('profiles::command_and_control::t1219::enabled', Boolean, 'first', false),
){
  $rules = [
    '-w /usr/bin/wget -p x -k t1219_remote_access_tools',
    '-w /usr/bin/curl -p x -k t1219_remote_access_tools',
    '-w /usr/bin/base64 -p x -k t1219_remote_access_tools',
    '-w /bin/nc -p x -k t1219_remote_access_tools',
    '-w /bin/nc.traditional -p x -k t1219_remote_access_tools',
    '-w /bin/netcat -p x -k t1219_remote_access_tools',
    '-w /usr/bin/ncat -p x -k t1219_remote_access_tools',
    '-w /usr/bin/ssh -p x -k t1219_remote_access_tools',
    '-w /usr/bin/socat -p x -k t1219_remote_access_tools',
    '-w /usr/bin/rdesktop -p x -k t1219_remote_access_tools'
  ]

  if $enabled {
    auditd::rule { $rules: }
  }
}
