# Docker TOCTOU
This is a toctou flaw found in "docker cp" command which has a race condition while dealing with symbolic links (links to other directories) paths. Since the 
docker engine runs with root priviledges, and malformed container could write to host system using root priviledges for a very short period of time. 

What we are looking for here in this threat hunt is a occurance (execve/syscall 59) of "docker cp" and watch for its priviledges is associated syscall. 
If the priviledges are of root, then we look for any container outbound write operation (syscall - *write*) on host filesystem. 

These situations should really be dealt with machine learning as, admins normally tend to trouble shoot using root and is very often.

## Query
lists all syscall events where docker cp has been used.
```
GET _search/?format=yaml
{
  "_source": ["EXECVE_b_allArgs", "b_auid", "b_euid", "b_msg_lport","m_host","h_msg","m_eventTs"],
  "size": 0,
  "query" : 
  {
    "bool" : 
    {
      "filter": 
      [
        {"range": {"m_eventTs": {"from": "now-30m","to": "now"}}},
        {"wildcard": {"_index": {"wildcard": "auditd*","boost": 1}}},
        {"exists": {"field": "h_type"}},
        {"exists": {"field": "EXECVE_b_allArgs"}},
        {"match_phrase": {"m_sourceType": "parsed.auditd"}}
      ], 
      "must": 
      [
        {"match_phrase": {"EXECVE_b_allArgs": "docker cp"}}
        ,{"match_phrase": {"b_syscall": "59"}}
      ],
      "should": [],
      "must_not": 
      [
        {"match_phrase": {"b_tty": "(none)"}}
      ]
    }
  }
  ,"aggs" : {"GroupByExecve" : {"terms" : {"field" : "EXECVE_b_allArgs.keyword","min_doc_count": 10}}}
}
```

## References 
ToCToU - Time-of-Check to Time-of-Use is an old vector which shows up in applications from time to time. This time, it was in docker.

https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use

https://symantec-enterprise-blogs.security.com/blogs/product-insights/containing-your-containers-its-time-batten-down-hatches

https://duo.com/decipher/docker-bug-allows-root-access-to-host-file-system
