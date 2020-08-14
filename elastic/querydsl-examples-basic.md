### Wildcarded Terms query
this is simply not possible is elasticsearch, use query string instead. If you have to load values from a file, the use painless 
scripts as a stored file.

```
Wildcard Terms

/* This query is working*/
GET /syslog_test2/_search/?format=yaml&size=1
{
  "query": 
  {
    "bool": 
    {
      "must": 
      [
        {"query_string": {
          "default_field": "host",
          "query": "host:*king* OR host:*local*"
        }}
      ],
      "must_not": 
      [
        {"match_phrase": {"host": "kingjulian"}}
      ],
      "filter": {"range": {"@timestamp": {"gte": "now-7d","lte": "now"}}}
    }
  },
  "_source": ["host", "ident.keyword", "message.keyword"]
}
```

/* This query is working*/
GET /syslog_test2/_search/?format=yaml&size=1
{
  "query": 
  {
    "bool": 
    {
      "must": 
      [
        {"query_string": {
          "default_field": "host",
          "query": "host:*king* OR host:*local*"
        }}
      ],
      "must_not": 
      [
        {"match_phrase": {"host": "kingjulian"}}
      ],
      "filter": {"range": {"@timestamp": {"gte": "now-7d","lte": "now"}}}
    }
  },
  "_source": ["host", "ident.keyword", "message.keyword"]
}
/* Testing if this query will work with array */
// Result - FAILED.
GET /syslog_test2/_search
{
  "query": 
  {
    "bool": 
    {
      "must": 
      [
        {"query_string": {
          "default_field": "host",
          "query": {"index": "host_lookup", "id": "1", "path": "record"}
        }}
      ],
      "must_not": 
      [
        {"match_phrase": {"host": "kingjulian"}}
      ],
      "filter": {"range": {"@timestamp": {"gte": "now-7d","lte": "now"}}}
    }
  }
}

//Create Lookup array in same index of events where parent search is working.
//Result - Success, note, intentionally chosen a long length doc id.
POST /syslog_test2/_doc/1001
{
  "record":   ["king","local*"],
  "lookupname":"myhost”
}
GET /syslog_test2/_doc/1001
{
  "query":{
    "match_all" : {}
  }
}
//Create Lookup array in seperate index.
//Result - Success
PUT /syslog_test2/_doc/1
{
  "record":   ["king","local*"],
  "lookupname":"myhost”
}
//Show lookup data from a seperate index
//Result - Success
GET /host_lookup/_search
{
"query": {"match_all": {}}
}
//Update Lookup array in a seperate index
//Result - Success.
POST host_lookup/_doc/1
{
  "record":   ["king","local"],
  "lookupname":”myhost”

}
GET /syslog_test2/_search?format=yaml&size=1
{
  "query": {
    //"terms": {"_id": [ "1001" ] },
    "query_string": {
      "default_field": "host",
      "query": "lookupname:myhost"
    }
  }
}

//Use of terms query - working.
GET /syslog_test2/_search
{
  "query": 
  {
    "bool": 
    {
      "must": 
      [
        {"terms": {"host": {"index": "host_lookup", "id":"1", "path":"record"}}}
        //{"wildcard": {"host.keyword": {"index": "host_lookup", "id": "1", "path": "record"}}}
      ],
      "must_not": 
      [
        {"match_phrase": {"host": "kingjulian"}}
      ],
      "filter": {"range": {"@timestamp": {"gte": "now-7d","lte": "now"}}}
    }
  }
}
//Use of should query - working.
GET /syslog_test2/_search
{
  "query": 
  {
    "bool": 
    {
      "should": [
        {"match_phrase": {"host": "king"}},
        {"match_phrase": {"host": "local"}},
        {"match_phrase": {"host": "panda"}},
        {"wildcard": {"host": {"value": "local"}}}
      ], 
      "filter": {"range": {"@timestamp": {"gte": "now-7d","lte": "now"}}}
    }
  }
}


GET /auditd/_search/?format=yaml&size=1
{
  "query": 
  {
    "bool": 
    {
      "must": 
      [
        {"query_string": {"default_field": "host","query": "host:*king* OR host:*local*"}},
        {"match_phrase": {"h.type": "USER_LOGIN"}},
        {"wildcard": {"b.msg": {"value": "*/usr/sbin/sshd*"}}}
      ],
      "must_not": 
      [
        {"match_phrase": {"host": "kingjulian"}}
      ],
      "filter": {"range": {"@timestamp": {"gte": "now-1y","lte": "now"}}}
    }
  },
  "_source": ["host", "ident", "message"]
}

GET /auditd/_search
{
    "size": 10,
    "query": {
    "range": {
      "b.saddr": {
        "gte": "10.0.0.0",
        "lt":  "192.255.255.255"
      }
    }
  }
}

GET auditd/_search
{
   "script_fields": {
       "x_addr": 
       {
           "script": "/([0-9]{1,3}+\\.[0-9]{1,3}+\\.[0-9]{1,3}+\\.[0-9]{1,3}+)/.matcher(doc['b.msg.keyword'])"
       }
   },
   "_source": "x_addr"
}


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
      def m = /^.*\.([a-z]+)$/.matcher(doc['b.msg.keyword'].value);if ( m.matches() ) {return m.group(1)} else {return "no match"}
      """
    }
  },
   "_source": ["x_addr", "b.msg"]
}

——
GET /auditd/_search?allow_partial_search_results=true
{
  "script_fields": 
  {
    "x_addr":
    {
      "script":
      """
      if (doc["h.type.keyword"].value == 'USER_LOGIN')
      {
        def ext_v = /addr\=([0-9]{1,3}+\.[0-9]{1,3}+\.[0-9]{1,3}+\.[0-9]{1,3}+)/.matcher(doc["b.msg.keyword"].value);
        if (ext_v.find ())
        { return ext_v.group (1) }
        else
        { return "kuch nahi mila" }
      }
      else { return "nothing_extracted"}
      """
    },
    "x_hostname": 
    {
      "script": 
      """
      if (doc["h.type.keyword"].value == 'USER_LOGIN')
      {
        def ext_v = /hostname\=([^\s]+)/.matcher(doc["b.msg.keyword"].value);
        if (ext_v.find ())
        { return ext_v.group (1) }
        else
        { return "kuch nahi mila" }
      }
      else { return "nothing_extracted"}
      """
    },
    "x_exe":
    {
      "script":
      """
      if (doc["h.type.keyword"].value == 'USER_LOGIN')
      {
        def ext_v = /exe\=([^\s]+)/.matcher(doc["b.msg.keyword"].value);
        if (ext_v.find ())
        { return ext_v.group (1) }
        else
        { return "kuch nahi mila" }
      }
      else { return "nothing_extracted"}
      """
    },
    "x_terminal":
    {
      "script":
      """
      if (doc["h.type.keyword"].value == 'USER_LOGIN')
      {
        def ext_v = /terminal\=([^\s]+)/.matcher(doc["b.msg.keyword"].value);
        if (ext_v.find ())
        { return ext_v.group (1) }
        else
        { return "kuch nahi mila" }
      }
      else { return "nothing_extracted"}
      """
    },
    "x_res":
    {
      "script":
      """
      if (doc["h.type.keyword"].value == 'USER_LOGIN')
      {
        def ext_v = /res\=([^\s]+)/.matcher(doc["b.msg.keyword"].value);
        if(ext_v.find())
        {return ext_v.group (1)}
        else
        {return "kuch nahi mila"}
      }
      else 
      {
        return "nothing_extracted"
      }
      """
    }
  }, 
  "_source": ["x_addr", "x_hostname","x_exe", "x_res"],
  "query" : 
  {
    "term": {
      "h.type.keyword": {
        "value": "USER_LOGIN"
      }
    }
  }
}

GET /auditd/_search?pretty=true
{
  "query": 
  {
    "bool": 
    {
      "must": 
      [
        {"wildcard": {"b.msg.keyword": "*/usr/sbin/sshd*"}},
        {
          "script": 
          {"script": 
            {
              "source": "boolean compare(Supplier s, def v) {return s.get() == v;}compare(() -> { if (doc[\"h.type.keyword\"].value == 'USER_LOGIN')\n      {\n        def ext_v = /addr\\=([0-9]{1,3}+\\.[0-9]{1,3}+\\.[0-9]{1,3}+\\.[0-9]{1,3}+)/.matcher(doc[\"b.msg.keyword\"].value);\n        if (ext_v.find ())\n        { return ext_v.group (1) }\n        else\n        { return \"no_match\" }\n      }\n      else { return \"no_match\"} }, params.value);",
              "lang": "painless",
              "params": {"value": "no_match"}
            }
          }
        }
      ],
      "filter": 
      {
        "term": {"h.type.keyword": "USER_LOGIN"}
      }
    }
  }
}

GET /auditd/_search?pretty=true
{
  "query": 
  {
    "bool" : 
    {
      "must" : 
      {
        "script" : 
        {
          "script" : 
          {
            "source":
            """
            
            """
          }
        }
      }
    }
  }
}
------------------------
GET /auditd/_search?pretty=true
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
  
} 
---------------------
GET /auditd/_search
{
  "query": 
  {
    "bool": 
    {
      "must": 
      [
        {
          "script": {"script": "_score * doc['b.msg.keyword'].value"}
        }
      ]
    }
  }
}
———————————
31st may
//This query demostrates on MVP, extraction of addr from b.msg, evaluate it against single value and show events which do not match.
GET /auditd/_search
{
  "version": true,
  "size": 500,
  "sort": [{"m.eventTs": {"order": "desc", "unmapped_type": "boolean"}}],
  "stored_fields": ["*"],
  "script_fields": 
  {
    "x_addr": {
      "script": {
        "source": "if (doc[\"h.type.keyword\"].value == 'USER_LOGIN')\n      {\n        def ext_v = /addr\\=([0-9]{1,3}+\\.[0-9]{1,3}+\\.[0-9]{1,3}+\\.[0-9]{1,3}+)/.matcher(doc[\"b.msg.keyword\"].value);\n        if (ext_v.find ())\n        { return ext_v.group (1) }\n        else\n        { return \"no_match\" }\n      }\n      else { return \"no_match\"}",
        "lang": "painless"
      }
    }
  },
  "docvalue_fields": [],
  "_source": {"excludes": []},
  "query": 
  {
    "bool": 
    {
      "must": [],
      "filter":
      [
        //{"match_all": {}},
        {"match_phrase": {"h.type.keyword": "USER_LOGIN"}}
        //,{"range": {"m.eventTs.keyword": {"gte": "1400110000", "lte": "1700110000"}}}
      ],
      "should": [],
      "must_not": 
      [
        {
          "script": 
          {
            "script": 
            {
              "source":"boolean compare(Supplier s, def v) {return s.get() == v;}compare(() -> { if (doc[\"h.type.keyword\"].value == 'USER_LOGIN')\n      {\n        def ext_v = /addr\\=([0-9]{1,3}+\\.[0-9]{1,3}+\\.[0-9]{1,3}+\\.[0-9]{1,3}+)/.matcher(doc[\"b.msg.keyword\"].value);\n        if (ext_v.find ())\n        { return ext_v.group (1) }\n        else\n        { return \"no_match\" }\n      }\n      else { return \"no_match\"} }, params.value);",
              "lang": "painless",
              "params": {"x_addr": "172.17.68.75"}
            }
          }
        }
      ]
    }
  },
  "highlight": 
  {
    "pre_tags": ["@kibana-highlighted-field@"],
    "post_tags": ["@/kibana-highlighted-field@"],
    "fields": {"*": {}},
    "fragment_size": 2147483647
  }
}

//Syntactically correct but exclusion is not in effect for scripted field.
GET /auditd/_search?pretty=true
{
  "version": true,
  "size": 500,
  "sort": [{"m.eventTs": {"order": "desc", "unmapped_type": "boolean"}}],
  "stored_fields": ["*"],
  "script_fields": 
  {
    "x_addr": {
      "script": {
        "source": "if (doc[\"h.type.keyword\"].value == 'USER_LOGIN')\n      {\n        def ext_v = /addr\\=([0-9]{1,3}+\\.[0-9]{1,3}+\\.[0-9]{1,3}+\\.[0-9]{1,3}+)/.matcher(doc[\"b.msg.keyword\"].value);\n        if (ext_v.find ())\n        { return ext_v.group (1) }\n        else\n        { return \"no_match\" }\n      }\n      else { return \"no_match\"}",
        "lang": "painless"
      }
    }
  },
  "docvalue_fields": [],
  "_source": {"excludes": []},
  "query": 
  {
    "bool": 
        {
          "must": [],
          "filter": 
          [
            {"match_phrase": {"h.type.keyword": "USER_LOGIN"}}
          ],
          "must_not": 
          [
            {
              "script": {
                "script": 
                {
                  "source": "boolean compare(Supplier s, def v) {return s.get() == v;}compare(() -> { if (doc[\"h.type.keyword\"].value == 'USER_LOGIN')\n      {\n        def ext_v = /addr\\=([0-9]{1,3}+\\.[0-9]{1,3}+\\.[0-9]{1,3}+\\.[0-9]{1,3}+)/.matcher(doc[\"b.msg.keyword\"].value);\n        if (ext_v.find ())\n        { return ext_v.group (1) }\n        else\n        { return \"no_match\" }\n      }\n      else { return \"no_match\"} }, params.value);",
                  "lang": "painless",
                  "params": {"values": ["172.17.68.75","10.0.254.44"]}
                }
              }
            }
          ]
        }
  }
}

// WORK on this - wildcard list. DONE. WORKING.
GET /auditd/_search?pretty=true
{
  "version": true,
  "size": 500,
  "sort": [{"m.eventTs": {"order": "desc", "unmapped_type": "boolean"}}],
  "stored_fields": ["*"],
  "docvalue_fields": [],
  "_source": {"excludes": []},
 "query": 
 {
   "bool": 
   {
     "filter": {"match_phrase": {"h.type.keyword": "USER_LOGIN"}},
     "must": 
     [
       {"wildcard": {"b.msg.keyword": {"value": "*/usr/sbin/sshd*"}}}
     ],
     "must_not": 
     [
       //{"terms": {"x_addr": ["10.0.254.44", "172.18.17.133"]}}, 
       {"wildcard": {"b.msg.keyword": {"value": "*addr=10.*"}}},
       {"wildcard": {"b.msg.keyword": {"value": "*addr=172.18.*"}}},
       {"wildcard": {"b.msg.keyword": {"value": "*addr=172.16.*"}}}
     ]
   }
 }
}

// BULK UPLOAD OF iplookup. DONE. WORKING.
POST /test1/_bulk?pretty&refresh
{ "index" : { "_index" : "test1", "_id" : "1" } }
{"desc": "private", "iprange": "?", "reason": "local_action"}
{ "index" : { "_index" : "test1", "_id" : "2" } }
{"desc": "private", "iprange": "::1", "reason": "local_action"}
{ "index" : { "_index" : "test1", "_id" : "3" } }
{"desc": "private", "iprange": "10.*", "reason": "local_reserved"}
{ "index" : { "_index" : "test1", "_id" : "4" } }
{"desc": "private", "iprange": "172.16.*", "reason": "local_reserved"}

//Aggregation example.
GET /test1/_search
{
  "_source": ["desc", "iprange", "reason"], 
  "size": 200,
  "aggs": 
  {
    "private_count": {
      "terms": {"field": "desc.keyword"}
    }
  }, 
  "query": 
  {
    "match_all": {}
  }
}

DELETE /ia003_test_lookup3/_doc/2

//show mapping based lookup.
GET /ia003_test_lookup3/_doc/1

//mapping based lookup created.
POST /ia003_test_lookup3/_doc/1
{
  "mappings" : 
  {
    "doc" : 
    {
      "date_detection" : false,
      "properties": 
      {
        "record": {"type": "keyword"},
        "ip_add": {"type": "ip"}
      }
    }
  },
  "record": ["10.*", "172.16.*", "172.18.*"],
  "ip_add": ["10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"],
  "lookupname":"ia003_test_lookup"
}

//nestedQueryIndex Setup
PUT /ia003_test_lookup_nested/_doc/1
{
  "mappings" : 
  {
    "properties" : 
    {
      "ip_add" : {"type" : ["nested", "ip"]}
    }
  },
  "ip_add": ["10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
}

GET /ia003_test_lookup_nested/_doc/1


GET /auditd/_search?pretty=true
{
  "version": true,
  "size": 500,
  "sort": [{"m.eventTs": {"order": "desc", "unmapped_type": "boolean"}}],
  "stored_fields": ["*"],
  "docvalue_fields": [],
  "_source": {"excludes": []},
 "query": 
 {
   "bool": 
   {
     "filter": {"match_phrase": {"h.type.keyword": "USER_LOGIN"}},
     "must": 
     [
       {"wildcard": {"b.msg.keyword": {"value": "*/usr/sbin/sshd*"}}}
     ],
     "must_not": 
     [
       //{"terms": {"b.msg.keyword": {"_index": "ia003_test_lookup4", "id":"1", "path":"ip_add"}}}, 
       {"wildcard": {"b.msg.keyword": {"value": "*addr=10.*"}}},
       {"wildcard": {"b.msg.keyword": {"value": "*addr=172.18.*"}}},
       {"wildcard": {"b.msg.keyword": {"value": "*addr=172.16.*"}}}
       //,{"wildcard": {"b.msg.keyword": {"value": {"_index": "ia003_test_lookup4", "id":"1", "path":"ip_add"}}}}
     ]
   }
 }
}
——————
