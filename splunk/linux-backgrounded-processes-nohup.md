# Interesting auditd logs processes which are backgrounded. MITRE - Exfil

## Purpose: Identify suspiciously backgrounded proccess (nohup). MITRE - Persistance

## Data Required: Auditd Syscall logs

## Collection Considerations: 
```
Parsing and enrichment of log data is done in Splunk. 
(Parsing means - extracting normalized fields and enrichment means conversion of IDs to names.)
Additonally, there is no actual syscall for backgrounded processes, hence we'll rely on open/evecve syscalls for commands involving nohup.
This specific hunt would not overlap with Suspicious process related hunts because, in auditd, we'd always collect "nohup" but never its process.
```

## Analysis Techniques: 
### Splunk Query
```
index=auditd* 
    [ search index=auditd_syscall syscall=* nohup 
    | fields host msg 
    | format] 
| transaction host msg
| rex field=_raw "proctitle=(?<FullCMD>.*.)"
| stats count by syscall FullCMD cwd success exit items auid uid gid euid suid fsuid tty comm exe host 
| sort - count

Results snapshot
syscall	FullCMD	cwd	success	exit	items	auid	uid	gid	euid	suid	fsuid	tty	comm	exe	host	count
execve	nohup bash -c sudo systemctl start fake-odo 	/root	no	ENOENT(No such file or directory)	1	test_user1	root	root	root	root	root	(none)	nohup	/usr/bin/nohup	dart-testhost.nodes.ad1.r1	24
execve	nohup python3 ./agent/beet_agent.py 	/home/opc	yes	0	2	test_user2	opc	opc	opc	opc	opc	(none)	nohup	/usr/bin/nohup	sea-dev-1-ad1-h	12
execve	nohup ./run.sh resolved-configs/r1u.conf 	/home/paregupt/netty	yes	0	2	test_user3	test_user1	posix_sparta	test_user3	test_user3	test_user3	pts0	nohup	/usr/bin/nohup	splat-proxy-se-xxx1a2.node.ad2.r1	9
execve	nohup dgmgrl -silent sys/knl_test7@orclp start observer 	/u02	no	ENOENT(No such file or directory)	1	opc	oracle	oinstall	oracle	oracle	oracle	pts14	nohup	/usr/bin/nohup	dart-testhost.nodes.ad1.r1	6
execve	nohup bash -c sudo systemctl start fake-odo 	/root	yes	0	2	test_user1	root	root	root	root	root	(none)	nohup	/usr/bin/nohup	dart-test-platform-01311.node.ad1.r1	4
execve	nohup nice 	/etc/sv/mysqld	yes	0	2	unset	osvc	osvc	osvc	osvc	osvc	(none)	nohup	/usr/bin/nohup	identity-fedration.node.ad1.r1	4
```
## Description: 
Malicious actors tend to background process to hide themselves from an watchfull user (or admin). To do this, attackers have used nohup in past because it provides
persistance benefits in addtion to hiding it from ps. 

The query above is in splunk and shows a msgID correlated audit records from linux boxes, where a process has been backgrounded using nohup. Note that FullCMD is a 
rex parsed field and does not always apply, tweeks are needed. 

The result set here shows some suspicous proccess which were backgrounded. 

## Other Notes: 
(Similar) https://attack.mitre.org/techniques/T1053/003/

Will contribute nohup very soon.

## More Info: 
https://redcanary.com/blog/rocke-cryptominer/

https://www.f5.com/labs/articles/threat-intelligence/new-jenkins-campaign-hides-malware--kills-competing-crypto-miner

https://medium.com/@smurf3r5/reverse-shells-d1c5e3430bc8
