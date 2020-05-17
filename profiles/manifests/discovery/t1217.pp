# A profile for controlling auditing around ATT&CK technique T1087
# URL: https://attack.mitre.org/techniques/T1087/
#
# @param enabled - boolean
class profiles::discovery::t1217 (

    $enabled = lookup('profiles::discovery::t1217::enabled', Boolean, 'first', true),
){
  if $enabled {
    $users.each |String $user| {
      $rules = ["-w /home/${user}/.mozilla -p x -k t1033_system_owner_user_discovery"]

  }
    auditd::rule { $rules: }
  }
}
