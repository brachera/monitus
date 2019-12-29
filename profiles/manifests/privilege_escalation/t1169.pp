# A profile for controlling auditing around ATT&CK technique T1169
# URL: https://attack.mitre.org/techniques/T1169/
#
# @param enabled - boolean
class profiles::privilege_escalation::t1169 (
  $enabled = lookup('profiles::privilege_escalation::t1169::enabled', Boolean, 'first', false),
){
  $rules = [
    '-w /bin/su -p x -k t1169_sudo',
    '-w /usr/bin/sudo -p x -k t1169_sudo',
    '-w /etc/sudoers -p rw -k t1169_sudo',
    '-a always,exit -F arch=b64 -S setresuid -F a0=0 -F exe=/usr/bin/sudo -k t1169_sudo',
    '-a always,exit -F dir=/home -F uid=0 -F auid>=1000 -F auid!=4294967295 -C auid!=obj_uid -k t1169_sudo'
  ]

  if $enabled {
    auditd::rule { $rules: }
  }
}
