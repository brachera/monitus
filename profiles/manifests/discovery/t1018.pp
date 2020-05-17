# A profile for controlling auditing around ATT&CK tecnique T1018
# URL: https://attack.mitre.org/techniques/T1018/
#
# @param enabled - boolean
class profiles::discovery::t1018 (
  $enabled = lookup('profiles::discovery::t1018', Boolean, 'first', true),
){
  $rules = ['-w /usr/bin/ping -p x -k t1018_remote_system_discovery',
            '-w /etc/hosts -p r -k t1018_remote_system_discovery']

  if $enabled {
    auditd::rule { $rules: }
  }
}
