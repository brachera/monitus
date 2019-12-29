# A profile for controlling auditing around ATT&CK technique T1083
# URL: https://attack.mitre.org/techniques/T1083/
#
# @param enabled - boolean
class profiles::discovery::t1083 (
    $enabled = lookup('profiles::discovery::t1083::enabled', Boolean, 'first', false),
) {
  $rules = [
    '-w /usr/bin/ls -p x -k t1083_file_and_directory_discovery',
    '-w /usr/bin/find -p x -k t1083_file_and_directory_discovery',
    '-w /usr/bin/locate -p x -k t1083_file_and_drectory_discovery'
  ]

  if $enabled {
    auditd::rule { $rules: }
  }
}
