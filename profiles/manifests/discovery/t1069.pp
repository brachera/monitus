# A profile for controlling auditing around ATT&CK tecnique T1069
# URL: https://attack.mitre.org/techniques/T1069/
#
# @param enabled - boolean
class profiles::discovery::t1201 (
  $enabled = lookup('profiles::discovery::t1069', Boolean, 'first', true),
){
  $rules = ['-w /usr/bin/groups -p x -k t1069_permission_groups_discovery',
            '-a exit.always -F arch=b64 -S getgroups -k t1069_permission_groups_discovery']

  if $enabled {
    auditd::rule { $rules: }
  }
}
