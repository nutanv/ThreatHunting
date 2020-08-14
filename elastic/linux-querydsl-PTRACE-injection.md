# Detect Suspicious use of PTRACE.
Attackers often use vulnerable processess to inject malware into them to achive multiple goals. Not limiting just to PrivEsc, obfuscation or plain persistance.
a common method used is PTRACE functions given by linux gcc.

## Query DSL Query - Note the syscalls.
```
GET auditd*/_search
{
  "_source": ["m_eventTs", "h_msg", "b_syscall", "b_auid", "b_uid", "b_comm", "b_exe", "m_host", "b_allArgs","PROCTITLE_b_proctitle", "b_success", "b_tty"],
  "query": 
  {
    "bool": 
    {
      "filter": 
      [
        {"match_phrase": {"m_host.keyword": "security-splunk-canary-01301.node.ad1.r2"}},
        {"range": {"m_eventTs": {"gte": "2020-06-10T03:00:00.000Z","lte": "2020-06-10T04:45:00.000Z"}}},
        {"exists": {"field": "h_type"}},
        {"exists": {"field": "b_syscall"}},
        {"match_phrase": {"b_syscall.keyword": "101"}}
        //,{"multi_match" : {"query": "nuvishwa", "fields": ["b_auid", "b_msg_acct"]}}
      ],
      "must_not": 
      [
        {"match_phrase": {"b_tty": "(none)"}}
      ],
      "must": 
      [
        {"exists": {"field": "b_allArgs"}},
        {"match_phrase": {"b_success.keyword": "yes"}}
      ],
      "should": 
      [
        {"wildcard": {"b_allArgs": {"value": "4207*"}}},
        {"wildcard": {"b_allArgs": {"value": "4206*"}}},
        {"wildcard": {"b_allArgs": {"value": "16*"}}},
        {"wildcard": {"b_allArgs": {"value": "14*"}}},
        {"wildcard": {"b_allArgs": {"value": "4204*"}}},
        {"wildcard": {"b_allArgs": {"value": "5*"}}},
        {"wildcard": {"b_allArgs": {"value": "4*"}}},
        {"wildcard": {"b_allArgs": {"value": "6*"}}}
      ],"minimum_should_match": 1
      
    }
  },
  "aggs": 
  {
    "transact_pid_count": 
    {
      "value_count": 
      {
        "script" : 
        {
          "source" :
          """
          doc['b_pid.keyword'].value
          """
        }
      }
    }
  }
}
```
