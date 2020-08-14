# NESTED AGGS-
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
