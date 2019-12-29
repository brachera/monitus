# A profile for controlling auditing around ATT&CK technique T1136
# URL: https://attack.mitre.org/techniques/T1136/
#
# @param enabled - boolean
class profiles::persistence::t1136 (
    $enabled = lookup('profiles::persistence::t1136::enabled', Boolean, 'first', false),
) {
  $rules = [
    '-w /usr/sbin/adduser -p x -k t1136_create_account',
    '-w /usr/sbin/luseradd -p x -k t1136_create_account',
    '-w /usr/sbin/useradd -p x -k t1136_create_account',
    '-w /usr/sbin/newusers -p x -k t1136_create_account',
    '-w /etc/passwd -p w -k t1136_create_account',
    '-w /etc/shadow -p w -k t1136_create_account'
  ]

  if $enabled {
    auditd::rule { $rules: }
  }
}
