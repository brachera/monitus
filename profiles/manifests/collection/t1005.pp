# A profile for controlling auditing around ATT&CK technique T1005
# URL: https://attack.mitre.org/techniques/T1005/
#
# @param enabled - boolean
class profiles::collection::t1005 (
  $enabled = lookup('profiles::collection::t1005::enabled', Boolean, 'first', false),
){
  $rules = [
    '-w /usr/bin/cp -p x -k t1005_data_from_local_system',
    '-w /usr/bin/dd -p x -k t1005_data_from_local_system'
  ]

  if $enabled {
    auditd::rule { $rules: }
  }
}
