# Monitor File movement commands in linux. 
Attackers often use inbuilt linux commands to move there "loot" out of the box. This threat hunt query written in QueryDSL (of elasticsearch) can list potential situations
of data transfer (implement a whitelist OR use Machine Learning algorithms).

## DSL Query
```
GET _search
{
  "_source": ["EXECVE_b_allArgs","PROCTITLE_b_proctitle", "b_auid", "b_uid", "b_comm","m_host","h_msg","m_eventTs"],
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
        {"exists": {"field": "PROCTITLE_b_proctitle"}},
        {"exists": {"field": "b_auid"}},
        {"terms": {"b_syscall": ["59", "2"]}},
        {"range": {"EXECVE_b_argc": {"gte": "3"}}},
        {"match_phrase": {"m_sourceType": "parsed.auditd"}}
      ], 
      "must": 
      [
        {"terms": {"b_comm": ["mv", "cp", "scp", "rename"]}},
        {
          "bool": 
          {
            "should": 
            [
              {"wildcard": {"EXECVE_b_allArgs.keyword": "*/usr/bin/*"}},
              {"wildcard": {"EXECVE_b_allArgs.keyword": "*/bin/*"}},
              {"wildcard": {"EXECVE_b_allArgs.keyword": "*/sbin/*"}}
            ], "minimum_should_match": 1
          }
        }
      ],
      "must_not": 
      [
        {"match_phrase": {"b_tty": "(none)"}},
        {"terms": {"b_auid": ["opc", "oracle", "unset"]}},
        {"terms": {"b_uid": ["root", "oracle", "opc", "unset"]}}
      ]
    }
  }
}
```

## Painless script used as whitelist.
```
NA
```
