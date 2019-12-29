# A profile for controlling auditing around ATT&CK technique t1168
# URL: https://attack.mitre.org/techniques/t1168/
#
# @param enabled - boolean
class profiles::persistence::t1168 (
    $enabled = lookup('profiles::persistence::t1168::enabled', Boolean, 'first', false),
) {
  $rules = [
    '-w /etc/cron.allow -p wa -k t1168_local_job_scheduling',
    '-w /etc/cron.deny -p wa -k t1168_local_job_scheduling',
    '-w /etc/cron.d/ -p wa -k t1168_local_job_scheduling',
    '-w /etc/cron.daily/ -p wa -k t1168_local_job_scheduling',
    '-w /etc/cron.hourly/ -p wa -k t1168_local_job_scheduling',
    '-w /etc/cron.monthly/ -p wa -k t1168_local_job_scheduling',
    '-w /etc/cron.weekly/ -p wa -k t1168_local_job_scheduling',
    '-w /etc/crontab -p wa -k t1168_local_job_scheduling',
    '-w /var/spool/cron/crontabs/ -k t1168_local_job_scheduling',
    '-w /etc/inittab -p wa -k t1168_local_job_scheduling',
    '-w /etc/init.d/ -p wa -k t1168_local_job_scheduling',
    '-w /etc/init/ -p wa -k t1168_local_job_scheduling',
    '-w /etc/at.allow -p wa -k t1168_local_job_scheduling',
    '-w /etc/at.deny -p wa -k t1168_local_job_scheduling',
    '-w /var/spool/at/ -p wa -k t1168_local_job_scheduling',
    '-w /etc/anacrontab -p wa -k t1168_local_job_scheduling',
    '-w /usr/bin/crontab -p x -k t1168_local_job_scheduling',
    '-w /usr/bin/at -p x -k t1168_local_job_scheduling'
  ]

  if $enabled {
    auditd::rule { $rules: }
  }
}
