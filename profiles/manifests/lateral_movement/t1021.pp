# A profile for controlling auditing around ATT&CK technique T1201
# URL: https://attack.mitre.org/techniques/T1201/
#
# @param enabled - boolean
class profiles::lateral_movement::t1021 (
  $enabled = lookup('profiles::lateral_movement::t1021::enabled', Boolean, 'first', false),
){
  $rules = [
    '-w /var/log/faillog -p wa -k t1021_remote_services',
    '-w /var/log/lastlog -p wa -k t1021_remote_services',
    '-w /var/log/tallylog -p wa -k t1021_remote_services',
    '-w /etc/ssh/sshd_config -k t1021_remote_services'
  ]

  if $enabled {
    auditd::rule { $rules: }
  }
}
