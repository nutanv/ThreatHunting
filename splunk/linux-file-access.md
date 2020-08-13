# Interesting auditd logs showing file access attempts. MITRE - Exfil

## Purpose: Identify orphan bash shells and interesting manual file access attempts.

## Data Required: Auditd Syscall logs

## Collection Considerations: 
```
Parsing and enrichment of log data is done in Splunk. 
(Parsing means - extracting normalized fields and enrichment means conversion of IDs to names.)
```

## Analysis Techniques: 
### Splunk Query
```
index=auditd_syscall syscall=open* (tty!="\(none\)" AND NOT comm IN (pool-*, seam, odoctl, ecracli, concat_certs.sh, os-updater, chef*))
| stats count by syscall success exit items auid uid gid euid suid fsuid tty comm exe host
| sort - count
```

## Description: 
Malicious actors tend to go after files to which they do not have access. To do so, they sometimes enumerate (or open) file permissions by simply opening them.
They might also perform tricks to relax restricted permission using exiting priviledged process on the box. Infact the whole operation could then be automated using 
scripts or programs. 
The query above list all user access attempts from a terminal (Use Pid PPid chaining to accertain automation scripts). 

## Other Notes: 
T1567
T1020


## More Info: MITRE ATT&K Exfil

https://attack.mitre.org/tactics/TA0010/
https://attack.mitre.org/techniques/T1020/
