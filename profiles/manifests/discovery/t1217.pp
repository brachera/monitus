# A profile for controlling auditing around ATT&CK technique T1217
# URL: https://attack.mitre.org/techniques/T1217/
#
# @param enabled - boolean
class profiles::discovery::t1217 (
    $enabled = lookup('profiles::discovery::t1217::enabled', Boolean, 'first', false),
){
  if $enabled {
    #For each places.sqlite file within /home directories
    $::mozilla_places_sqlites.split('\n').each |String $place_sqlite| {
    auditd::rule { "-w ${place_sqlite} -p rx -k t1217_browser_bookmark_discovery": }
    }
  }
}
