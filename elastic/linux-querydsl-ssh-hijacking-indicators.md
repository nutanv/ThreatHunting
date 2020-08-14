# SSH Abuse Detection Example
In linux systems, attackers often use ssh to move between machines or ssh to localhost with an elevated account to either to gain access or escalate priviledges.
The query leverages indicators extracted from an SSH Hijack tests done b/w two machines to list potential abuse. 
We are looking for - 
1. use of environment variable SSH_AUTH_SOCK in ssh command.
2. use of ssh's '-o' option to override the .ssh/config parameters controling default behaviour of ssh client. This could lead to having insecure params enabled.
3. use of ssh-agent to logon. (use a whitelist or a threshold).
4. use of ssh-add, which would add a key to ssh-agent. (if no auth is provided, ssh will pass ssh-agent's contents to destination for auth) ssh-agent is similar to
lsas process in windows. linux's passwd/shadow files are equivalent of SAM files in windows.

```
GET _search
{
  "query": 
  {
    "bool": 
    {
      "filter": 
      [
        {"range": {"m_eventTs": {"from": "now-30d","to": "now"}}},
        {"wildcard": {"_index": {"wildcard": "auditd*","boost": 1}}},
        {"exists": {"field": "h_type"}},
        {"match_phrase": {"h_type.keyword": "SYSCALL"}},
        {"match_phrase": {"b_exe.keyword": "/usr/bin/ssh"}},
        {"exists": {"field": "PROCTITLE_b_proctitle"}},
        {"match_phrase": {"m_sourceType": "parsed.auditd"}}
      ],
      "must_not": 
      [
        {"match_phrase": {"b_tty": "(none)"}}
      ],
      "must": 
      [
        {"match_phrase": {"b_exe.keyword": "/usr/bin/ssh"}},
        {"match_phrase": {"PROCTITLE_b_proctitle": "ssh"}},
        {"script" : {"script" : {"id": "LM-002A-Whitelist" }}}
      ], 
      "should": 
      [
        {"match_phrase": {"PROCTITLE_b_proctitle": "-A"}},
        {"match_phrase": {"PROCTITLE_b_proctitle": "-R"}},
        {"match_phrase": {"PROCTITLE_b_proctitle": "-O"}},
        {"match_phrase": {"PROCTITLE_b_proctitle": "-f"}},
        {"match_phrase": {"PROCTITLE_b_proctitle": "SSH_AUTH_SOCK"}},
        {"match_phrase": {"PROCTITLE_b_proctitle": "ssh-copy-id"}},
        {"match_phrase": {"PROCTITLE_b_proctitle": "ssh-add"}},
        {"match_phrase": {"PROCTITLE_b_proctitle": "ssh-agent"}},
        {"query_string": {"default_field": "PROCTITLE_b_proctitle","query": "(ssh \\-o) AND (ControlMaster\\=yes OR ControlPath\\= OR ControlPersist\\=yes OR ForwardAgent\\=yes) AND NOT (grep \\-\\-color\\=auto AND \\-t \\-\\-ssh\\-agent)"
        }}
      ],
      "adjust_pure_negative": true,
      "minimum_should_match": "1",
      "boost": 1
    }
  },
  "_source": 
  {
    "includes": 
    [
      "m_eventTs",
      "m_host",
      "h_msg",
      "PROCTITLE_b_proctitle",
      "b_auid",
      "b_tty",
      "b_exe"
    ],
    "excludes": []
  }
}
```

## SSH Abuse Whitelist Example using Painless Script.
```
POST _scripts/LM-002A-Whitelist
GET _scripts/LM-002A-Whitelist
{
  "script": 
  {
    "lang": "painless",
    "source": 
      """
        String proctitle = "PROCTITLE_b_proctitle.keyword";
        String auid = "b_auid.keyword";
        String host= "m_host.keyword";
        String tty= "b_tty.keyword";
        String uid= "b_uid.keyword";
        Map map1 = ["auid":"ksplinte", "host": "us-ashburn-bastion-*", "reference": "https://jira.oci.oraclecorp.com/browse/DARTOPS-3329", "tty": "*", "uid": "ksplinte", "x_command":" *ssh -A 10.0.10.130*"];
        Map map2 = ["auid":"ksplinte", "host": "us-ashburn-bastion-*", "reference": "https://jira.oci.oraclecorp.com/browse/DARTOPS-3329", "tty": "*", "uid": "ksplinte", "x_command":"*ssh -A 172.16.104.186*"];
        Map map3 = ["auid":"unset", "host": "*", "reference": "https://jira.oci.oraclecorp.com/browse/DARTOPS-3343", "tty": "\\(none\\)", "uid": "*", "x_command":"*"];
        Map map4 = ["auid":"gpresura", "host": "teamcity-ocicorp-*", "reference": "https://jira.oci.oraclecorp.com/browse/DARTOPS-3348", "tty": "*", "uid": "*", "x_command":"*ssh -A*"];
        Map map5 = ["auid":"secscan", "host": "*jenkinsmaster*", "reference": "https://jira.oci.oraclecorp.com/browse/DARTOPS-3431", "tty": "*", "uid": "secscan", "x_command":"*ssh-agent*"];
        Map map6 = ["auid":"*", "host": "*", "reference": "https://jira.oci.oraclecorp.com/browse/DARTOPS-3574", "tty": "*", "uid": "*", "x_command":"*ssh-add -e /usr/local/lib/opensc-pkcs11.so*"];
        Map map7 = ["auid":"*", "host": "*", "reference": "https://jira.oci.oraclecorp.com/browse/DARTOPS-3831", "tty": "*", "uid": "*", "x_command":"ssh-add -L*"];
        Map map8 = ["auid":"*", "host": "*", "reference": "https://jira.oci.oraclecorp.com/browse/DARTOPS-3831", "tty": "*", "uid": "*", "x_command":"ssh-add -l*"];
        
        List list = [map1, map2, map3, map4, map5, map6, map7, map8];
        
        for (int i = 0; i < list.length; i++) {
              boolean auidFound = false;
              boolean hostFound = false;
              boolean commandFound = false;
              boolean ttyFound = false;
              boolean uidFound = false;
              if(!list[i].auid.equals("*")){
                if(doc[auid].size() >0){
                  if(doc[auid].value.toLowerCase().contains(list[i].auid.toLowerCase())){
                    auidFound = true;
                  }
                }
              }
              else{
                auidFound = true;
              }
              if(!list[i].host.equals("*")){
                if(doc[host].size() > 0){
                  if(doc[host].value.toLowerCase().contains(list[i].host.toLowerCase())){
                    hostFound = true;
                  }
                }
              }
              else{
                hostFound = true;
              }
              if(!list[i].x_command.equals("*")){
                if(doc[proctitle].size() > 0){
                  if(doc[proctitle].value.toLowerCase().contains(list[i].x_command.toLowerCase())){
                    commandFound = true;
                  }
                }
              }
              else{
                commandFound = true;
              }
              if(!list[i].tty.equals("*")){
                if(doc[tty].size() > 0){
                  if(doc[tty].value.toLowerCase().contains(list[i].tty.toLowerCase())){
                    ttyFound = true;
                  }
                }
              }
              else{
                ttyFound = true;
              }
              if(!list[i].uid.equals("*")){
                if(doc[uid].size() > 0){
                  if(doc[uid].value.toLowerCase().contains(list[i].uid.toLowerCase())){
                    uidFound = true;
                  }
                }
              }
              else{
                uidFound = true;
              }
              if(auidFound && hostFound && commandFound && ttyFound && uidFound){
                return false;
              }
            }
            return true;
      """
  }
}
```
