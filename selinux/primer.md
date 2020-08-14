# What is SELinux
The SELinux enhancement to the Linux kernel implements the Mandatory Access Control (MAC) policy, which allows you to define a security policy that 
provides granular permissions for all users, programs, processes, files, and devices. 
The kernel's access control decisions are based on all the security relevant information available, and not solely on the authenticated user identity.
Traditionally (Before SELinux or without it), it would have been a sole responsibility of Discretionary Access Control (DAC) policy to control access. 
This policiy depends on user identity and ownership information available to kernel to control access. 
If the user is root or the application is setuid or setgid to root, the process can have root-access control over the entire file system.

## Labels

Every thing in linux OS which has SELinux, has labels. These labels are formed using four items:-
User
Role
Type
Context

To enhance security, one must use all combinations of this. But it’s the “type” portion of label, which is most important. 

### To list these labels, we can use “-Z or -z” command arguments. 
For labels of running processes, “ps -Z”.
For labels of files, “ls -Z”.
For labels of user, “id -Z”.
For labels of ports/sockets, “ss -z”.

### SeLinux Modes of enablements - Three - The persist your choice of mode, edit /etc/selinux/config

#### Permissive - 
In this mode, SELinux acts as watchman, it notes every system activity but does not stop or allow anything. 
SeLinux will behave like it knows what to do, its logging will show, that certain action would have been taken, but no action is actually taken. Just plain watchdog without action. Logging is done in AVC.

#### Enforced mode - 
Everything of Permissive mode, plus action. In enforced mode, SELinux behaves like police. 
It will allow or deny system activity based on configured policies. Writes a log in AVC.

#### Disabled - 
No SeLinux effect, as good as it not being there. Since you can’t really uninstall Selinux from kernel, this option is extended for Admins to use at their own discretion. 

```
[nuvishwa@testbox ~]$ getenforce
Enforcing
[nuvishwa@testbox ~]$
 
[nuvishwa@testbox ~]$ sudo cat /etc/selinux/config
# This file controls the state of SELinux on the system.
# SELINUX= can take one of these three values:
#     enforcing - SELinux security policy is enforced.
#     permissive - SELinux prints warnings instead of enforcing.
#     disabled - No SELinux policy is loaded.
SELINUX=enforcing
# SELINUXTYPE= can take one of three two values:
#     targeted - Targeted processes are protected,
#     minimum - Modification of targeted policy. Only selected processes are protected.
#     mls - Multi Level Security protection.
SELINUXTYPE=targeted
[nuvishwa@testbox ~]$

```
## Controlling SELinux -
SeLinux Mode Config File - /etc/selinux/config

SeLinux Manage Config File - /etc/selinux/semanage.conf

SeLinux Modules Config Files - /etc/security/*.conf

## About Basic Interaction -

SeStatus - This command will show what is the status of Selinux on this system.

## The way SELinux is deployed is by the means of packages, below is a summary extracted from OL Site -

| Package | Description |
| --- | --- |
| policycoreutils | Provides utilities such as load_policy, restorecon, secon, setfiles, semodule, sestatus, and setsebool for operating and managing SELinux.|
| libselinux | Provides the API that SELinux applications use to get and set process and file security contexts, and to obtain security policy decisions.|
| selinux-policy | Provides the SELinux Reference Policy, which is used as the basis for other policies, such as the SELinux targeted policy.|
| selinux-policy-targeted | Provides support for the SELinux targeted policy, where objects outside the targeted domains run under DAC.|
| libselinux-python | Contains Python bindings for developing SELinux applications.|
| libselinux-utils | Provides the avcstat, getenforce, getsebool, matchpathcon, selinuxconlist, selinuxdefcon, selinuxenabled, setenforce, and togglesebool utilities.|

## SELinux Logging
SELinux can log everything (smile). It can log all granted accesses and access denials.

Logs are generally written to /var/log/avc.log but I strongly believe it's piped to /var/log/audit.log in OCI environment. Those logs are then parsed into syscall index, type=AVC. 

Also note that there are SELinux-aware Application Events which are generated for SYSTEM ERRORS, POLICY LOAD etc. 
These events are built on top of SELinux crude events. One example can be seen in auditd_authentication index as "USER_ERR".

## What is in it for Hunting Team
1. Detect Process Execution Anomaly.
2. Root kit detections using denials.
3. What is new in the environment.
4. No selinux policy means even legit services will go blocked.
5. Catch - Although robust,  selinux is a label based access control mechanishm aiding to host protection AND not an replacement of IAM (Access Control) OR Antimalware solutions.

## Selinux denials are logged into AVC, below is a drill down of two sample events.

```
Event 1
	
type=AVC msg=audit(12/06/2019 02:49:53.986:64553263) : avc: denied { nnp_transition } for pid=43444 comm=uc-spawn scontext=system_u:system_r:unconfined_t:s0 tcontext=unconfined_u:system_r:container_t:s0:c9,c856 tclass=process2 permissive=0

Breakup :-

type=AVC #This means log is of type AVC.

msg=audit(12/06/2019 02:49:53.986:64553263) # message ID.

avc: denied { nnp_transition }  # SELinux "denied" to grant "nnp_transition" capability. (Read More here about nnp_transitions)

for pid=43444 # process ID of requesting executable.

comm=uc-spawn # command issued at prompt (generally the process name)

scontext=system_u:system_r:unconfined_t:s0 # Security context (domain) of source (note the 's' in start), in this case, associated with process "uc-spawn"

tcontext=unconfined_u:system_r:container_t:s0:c9,c856 # Security context (domain) of target (note the 't' in start), in this case associated with permission "nnp_transition".

tclass=process2 # target class is process (Read more here https://selinuxproject.org/page/NB_ObjectClassesPermissions#Process_Object_Class)

permissive=0 # Perissive mode is disabled.

```

```
Event 2

type=AVC msg=audit(12/06/2019 07:21:54.234:2472480919) : avc: denied { getattr } for pid=52382 comm=mdadm path=/dev/shm/hm_sar.lock dev="tmpfs" ino=51807 scontext=system_u:system_r:mdadm_t:s0-s0:c0.c1023 tcontext=system_u:object_r:tmpfs_t:s0 tclass=file permissive=0 

Breakup :-

avc: denied { getattr } # SELinux "denied" to grant "getattr" operation (syscall).

for pid=52382 # process ID requesting "getattr"

comm=mdadm # Command Issued at prompt.

path=/dev/shm/hm_sar.lock # This path of the target of which "getattr" was requested for. This field is also noted as 'name' is some versions.

dev="tmpfs" ino=51807 # Device on which target is located and Its INODE number.

scontext=system_u:system_r:mdadm_t:s0-s0:c0.c1023 # SELinux context of source (requesting process, here "mdadm")

tcontext=system_u:object_r:tmpfs_t:s0 #SELinux context of target (requested for, in this case item noted in 'path')

tclass=file # target's class of object, in this case its a file.

permissive=0 # Perissive mode is disabled.
```
## References:-

https://docs.oracle.com/en/operating-systems/oracle-linux/7/security/ol7-selinux-sec.html

https://selinuxproject.org/page/AVCRules#Access_Vector_Rules

https://selinuxproject.org/page/NB_AL#AVC_Audit_Message

https://selinuxproject.org/page/NB_ObjectClassesPermissions

https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/entry/syscalls/syscall_64.tbl

https://github.com/SELinuxProject/selinux/blob/master/libselinux/include/selinux/av_permissions.h

https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/selinux_users_and_administrators_guide/index

https://wiki.gentoo.org/wiki/SELinux/Tutorials/Where_to_find_SELinux_permission_denial_details
