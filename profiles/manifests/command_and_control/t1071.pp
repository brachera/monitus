# A profile for controlling auditing around ATT&CK technique T1071
# URL: https://attack.mitre.org/techniques/T1071/
#
# @param enabled - boolean
class profiles::command_and_control::t1071 (
  $enabled = lookup('profiles::command_and_control::t1071::enabled', Boolean, 'first', false),
){
  $rules = [
    '-w /etc/pam.d/ -p wa -k t1071_standard_application_layer_protocol',
    '-w /etc/security/limits.conf -p wa  -k t1071_standard_application_layer_protocol',
    '-w /etc/security/pam_env.conf -p wa -k t1071_standard_application_layer_protocol',
    '-w /etc/security/namespace.conf -p wa -k t1071_standard_application_layer_protocol',
    '-w /etc/security/namespace.init -p wa -k t1071_standard_application_layer_protocol'
  ]

  if $enabled {
    auditd::rule { $rules: }
  }
}
