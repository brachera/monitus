# A profile for controlling auditing around ATT&CK technique T1105
# URL: https://attack.mitre.org/techniques/T1105/
#
# @param enabled - boolean
class profiles::discovery::t1105 (
  $enabled = lookup('profiles::discovery::t1105', Boolean, 'first', true),
){
  $rules = ['-w /usr/bin/ftp -p x -k t1201_remote_file_copy',
            '-w /usr/bin/scp -p x -k t1201_remote_file_copy',
            '-w /usr/bin/sftp -p x -k t1201_remote_file_copy']

  if $enabled {
    auditd::rule { $rules: }
  }
}
