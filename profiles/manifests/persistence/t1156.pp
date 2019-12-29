# A profile for controlling auditing around ATT&CK technique T1156
# URL: https://attack.mitre.org/techniques/T1156/
#
# @param enabled - boolean
class profiles::persistence::t1156 (
    $enabled = lookup('profiles::persistence::t1156::enabled', Boolean, 'first', false),
) {
  $rules = [
    '-w /etc/profile.d/ -k t1156_bash_profile_and_bashrc',
    '-w /etc/profile -k t1156_bash_profile_and_bashrc',
    '-w /etc/shells -k t1156_bash_profile_and_bashrc',
    '-w /etc/bashrc -k t1156_bash_profile_and_bashrc',
    '-w /etc/csh.cshrc -k t1156_bash_profile_and_bashrc',
    '-w /etc/csh.login -k t1156_bash_profile_and_bashrc'
  ]

  if $enabled {
    auditd::rule { $rules: }
  }
}
