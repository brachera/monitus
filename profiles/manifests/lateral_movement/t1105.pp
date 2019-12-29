# A profile for controlling auditing around ATT&CK technique T1105
# URL: https://attack.mitre.org/techniques/T1105/
#
# @param enabled - boolean
class profiles::lateral_movement::t1105 (
  $enabled = lookup('profiles::lateral_movement::t1105::enabled', Boolean, 'first', false),
){
  $rules = [
    '-w /usr/bin/ftp -p x -k t1105_remote_file_copy',
    '-w /usr/bin/scp -p x -k t1105_remote_file_copy',
    '-w /usr/bin/sftp -p x -k t1105_remote_file_copy'
  ]

  if $enabled {
    auditd::rule { $rules: }
  }
}
