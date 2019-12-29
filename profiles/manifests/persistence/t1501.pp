# A profile for controlling auditing around ATT&CK technique T1501
# URL: https://attack.mitre.org/techniques/T1501/
#
# @param enabled - boolean
class profiles::persistence::t1501 (
  $enabled = lookup('profiles::persistence::t1501::enabled', Boolean, 'first', false),
){
  $rules = [
    '-w /etc/systemd/system/ -k t1501_systemd_service',
    '-w /usr/lib/systemd/system/ -k t1501_systemd_service',
    '-w /run/systemd/system/ -k t1501_systemd_service'
  ]

  if $enabled {
    auditd::rule { $rules: }
  }
}
