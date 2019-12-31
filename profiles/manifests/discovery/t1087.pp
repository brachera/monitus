# A profile for controlling controls around ATT&CK technique T1087
    # URL: https://attack.mitre.org/techniques/T1087/
    #
    # @param enabled - boolean
class profiles::discovery::t1087 (

    $enabled = lookup('profiles::discovery::t1087::enabled', Boolean, 'first', true),
){
  $rules = ['-w /etc/passwd -p r -k t1087_account_discovery', '-w /etc/shadow -p r -k t1087_account_discovery']

  if $enabled {
    auditd::rule { $rules: }
  }
}