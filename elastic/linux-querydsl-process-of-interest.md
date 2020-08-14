# Suspicious Linux Proccesses with whitelist.
ssh and bash related processes are interesting procesess in linux and should be watched.There is also a ton of noise because of legit uses, 
hence an environment specific whitelist should be implemented. We are implementing a whitelist using a painless script.

## Detection Query 
```
GET /_search
{
  "size": 0,
  "_source": ["m_host","b_auid","b_exe","PATH_b_name","CWD_b_cwd", "h_msg","PROCTITLE_b_proctitle"],
  "query": 
  {
    "bool": 
    {
      "filter": 
      [
        {"range": {"m_eventTs": {"from": "now-1h","to": "now"}}},
        {"wildcard": {"_index": {"wildcard": "auditd*","boost": 1}}},
        {"exists": {"field": "h_type"}},
        {"exists": {"field": "PROCTITLE_b_proctitle"}},
        {"match_phrase": {"h_type.keyword": "PROCTITLE_b_proctitle"}},
        {"match_phrase": {"m_sourceType": "parsed.auditd"}}
      ],
      "must": 
      [
        {"script": {"script": {"id": "XQ-010-Whitelist"}}}
      ],
      "must_not": [
        {"wildcard":{"PROCTITLE_b_proctitle.keyword" : "ssh -i"}},
        {"wildcard":{"PROCTITLE_b_proctitle.keyword" : "\tssh"}},
        {"wildcard":{"PROCTITLE_b_proctitle.keyword" : ".sh -i"}}
      ],
      "should": 
      [
        {"wildcard":{"PROCTITLE_b_proctitle.keyword" : "*import pty*"}},
        {"wildcard":{"PROCTITLE_b_proctitle.keyword" : "*os.system\\(*"}},
        {"wildcard":{"PROCTITLE_b_proctitle.keyword" : "*bash \\-i*"}},
        {"wildcard":{"PROCTITLE_b_proctitle.keyword" : "*exec \"/bin/sh\"*"}},
        {"wildcard":{"PROCTITLE_b_proctitle.keyword" : "*exec \"/bin/bash\"*"}},
        {"wildcard":{"PROCTITLE_b_proctitle.keyword" : "*/bin/sh -i*"}}
      ], "minimum_should_match": 1
    }
  }
}
```

## Sample Whitelist query 
```
POST _scripts/XQ-013-Whitelist
{
  "script" : 
  {
    "lang": "painless",
    "source": 
            """
            String auid = "b_auid.keyword";
            String host= "m_host.keyword";
            String x_cmd = "PROCTITLE_b_proctitle.keyword";
            Map map1 = ["auid": "*", "host": "*", "x_cmd": "*unix:///run/odo/docker.sock exec -i -t -u odosvc*", "reference": "DARTOPS-3894"];
            List list = [map1];
            for (int i=0; i< list.length; i++)
            {
              boolean auidFound = false;
              boolean hostFound = false;
              boolean x_cmdFound = false;
              if(!list[i].auid.equals("*"))
              {
                if(doc[auid].size() >0)
                {
                  if(doc[auid].value.toLowerCase().contains(list[i].auid.toLowerCase()))
                  {auidFound = true;}
                }
              }
              else {auidFound = true;}
              if(!list[i].host.equals("*"))
              {
                if(doc[host].size() >0)
                {
                  if(doc[host].value.toLowerCase().contains(list[i].host.toLowerCase()))
                  {hostFound = true;}
                }
              }
              else {hostFound = true;}
              if(!list[i].x_cmd.equals("*"))
              {
                if(doc[x_cmd].size() >0)
                {
                  if(doc[x_cmd].value.toLowerCase().contains(list[i].x_cmd.toLowerCase()))
                  {x_cmdFound = true;}
                }
              }
              else {x_cmdFound = true;}
              if(auidFound && hostFound && x_cmdFound)
              {return false;}
            }
            return true;
            """
  }
}
```
