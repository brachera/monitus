# A profile for controlling auditing around ATT&CK tecnique T1018
# URL: https://attack.mitre.org/techniques/T1018/
#
# The rpm command, coupled with arguments "-qa", can be used to
# discover installed software 
#
# Similarly, the command "yum list installed" will show packages
# installed on the system
#
# @param enabled - boolean
class profiles::discovery::t1518 (
  $enabled = lookup('profiles::discovery::t1518', Boolean, 'first', false),
){
  $rules = [
    '-w /usr/bin/rpm -p x -k t1518_software_discovery',
    '-w /usr/bin/yum -p x -k t1518_software_discovery'
  ]

  if $enabled {
    auditd::rule { $rules: }
  }
}
