# Extract fields form raw events (or a unparsed sub field).

## This query successfully extracts a field via regex in painless. (Scripted Field.)
```
GET /auditd/_search/?size=1
{
  "query" : {
        "term" : { "h.type.keyword": "USER_LOGIN" }
    },
  "script_fields": {
    "x_addr": 
    {
      "script": 
      """
      if (doc["b.msg.keyword"].value != null) { def m = /([0-9]{1,3}+\.[0-9]{1,3}+\.[0-9]{1,3}+\.[0-9]{1,3}+)/.matcher(doc["b.msg.keyword"].value); 
      if (m.find()) { return m.group(1) } else { return "no match" } } else { return "NULL"}
      """
    }
  },
   "_source": ["x_addr", "b.msg"]
}
```
## Below query matches value of a regular expression and based on it, takes an action. 
In this case, we are returning custom message “addr_e” for true and “add_n” for false 
```
GET /auditd/_search/?size=1
{
  "query" : {
        "term" : { "h.type.keyword": "USER_LOGIN" }
    },
  "script_fields": {
    "x_addr": 
    {
      "script": 
      """
      if (doc['b.msg.keyword'].value =~ /([0-9]{1,3}+\.[0-9]{1,3}+\.[0-9]{1,3}+\.[0-9]{1,3}+)/) {return "addr_e"} else {return "addr_n"}
      """
    }
  },
   "_source": ["x_addr", "b.msg"]
}

```

## Base query on which I initially started to work with
This is the query where m.matches was returning false and entering else portion all the times (NOT WORKING BASICALLY). Reason is, m.matches evaluates the regex with entire field and whole field should match. Where as for field extraction, we need m.find, which matches any substring with regex. 

```
GET /auditd/_search/?size=1
{
  "query" : {
        "term" : { "h.type.keyword": "USER_LOGIN" }
    },
  "script_fields": {
    "x_addr": 
    {
      "script": "if (doc[\"b.msg.keyword\"].value != null){ def m = /([0-9]{1,3}+\\.[0-9]{1,3}+\\.[0-9]{1,3}+\\.[0-9]{1,3}+)/.matcher(doc[\"b.msg.keyword\"].value); if (m.matches ()) { return m.group (1) } else { return \"no match\" } } else { return \"NULL\"}"
    }
  },
   "_source": "x_addr"
}

```

# ScriptScore
```
GET /auditd/_search?scroll=24m
{
  "query": 
  {
    "function_score": 
    { 
      "query": {"match_all": {}},
      "min_score": 1,
      "script_score": 
      {
        "script": 
        { 
          "source": "def total = 0; for (int i = 0; i < doc['b.msg.keyword'].length; i++)  { if (doc['b.msg.keyword'][i] == 'novel'){ total += 1;} else if (doc['b.msg.keyword'][i] == 'classics') {total+=10;} else {total+=20}} return total;",
          "lang": "painless"
        }
      }
    }
  } 
```

# Nested Bool Query
```
GET /auditd/_search?scroll=24m
{
  "query": 
  {
    "bool": 
    {
      "must": 
      [
        {"wildcard": {"b.msg": "*sshd*"}},
        {
          "bool": 
          {
            "must": 
            [
              {"match_phrase": {"h.type": "USER_LOGIN"}}
            ]
          }
        }
      ]
    }
  }
}
```

# Nested Aggregrations -
```
GET auditd*/_search/?size=0&format=yaml
{
  "aggs" : 
  {
    "ocid_count" : 
    {
      "value_count" : {"field" : "m_resId.keyword" }},
      "group_by_status": {"terms": {"field": "m_resId.keyword"}
      ,"aggs": {"host_count": {"terms": {"field": "m_host.keyword","size": 10}}}
      //,"aggs": {"host_count": {"value_count": {"field": "m_host.keyword"}},"group_by_host": {"terms": {"field": "m_host.keyword"}}}
    }
  },
  //"aggs": {
  //  "hosts_reporting": 
  //  {
      //"terms":{"field": "m_resId.keyword","order": {"_count": "desc"}},
      //"aggs": {"rock": {"filter": {"exists": {"field": "m_host"}}, "aggs": {"host_stats": {"terms": {"field": "m_host.keyword"}}}}},
      //"aggs": {"hosts_stats": {"terms": {"field": "m_host.keyword","size": 10}}},
      //"cardinality":{"field":"m_resId.keyword"}
      //"aggs": {"hosts_stats": {"cardinality": {"field": "m_host.keyword"}}}
  //  }
  //},
 "stored_fields": ["*"],
  "script_fields": {},
  "docvalue_fields":
  [
    {"field": "m_eventTs","format": "date_time"},
    {"field": "m_ingestTs","format": "date_time"},
    {"field": "m_parseTs","format": "date_time"}
  ],
  "_source": 
  {
    "excludes": "*",
    "includes": ["aggregations.hosts_reporting.buckets"]
  },
  "query": {
    "bool": {
      "must": [],
      "filter": 
      [
        {"match_all": {}},
        {"exists": {"field": "m_resId.keyword"}},
        {"range": {"m_eventTs": {"gte": "now-10d","lte": "now"}}}
      ],
      "should": [],
      "must_not": []
    }
  } 
}
```
