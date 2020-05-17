# A profile for controlling auditing around ATT&CK tecnique T1201
# URL: https://attack.mitre.org/techniques/T1201/
#
# @param enabled - boolean
class profiles::discovery::t1201 (
  $enabled = lookup('profiles::discovery::t1021', Boolean, 'first', true),
){
  $rules = ['-w /etc/pam.d/common-password -p wa -k t1201_password_policy_discovery']

  if $enabled {
    auditd::rule { $rules: }
  }
}
