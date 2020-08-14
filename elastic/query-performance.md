# Performance - Focus by Security engineering on query performance.

## Took value
shows time in milliseconds, it shows totalled up time of queue wait+query processing time. 
It does not include, query serialisation/deserialisation AND result serialisation/deserialisation time between client and es server. 

Now, some definitions from "Results" json -

1. "took" : 45 --> This means, ES took 45 miliseconds to process the query and match documents. This includes any queue wait times or shard processing time involved. Also NOTE that, this does NOT include any serialization/deserialization time taken between client and server, i.e user and es server via DSL. 

2. "timed_out" : false --> This means, the ES did not time-out this query. It does reflect a perfectly optimised query but it does reflect that the query was sufficiently good enough to get handled by ES.

3. "_shards" : this is the section which tells, how many different shards were this query was executed. Performance indicator would be "skipped" OR "failed", any value appearing in those two fields should be backed by SIEM Engg. A shard is basically a logical partition in ES which exists only one on a node. A index can spread over multiple shards. This is done to increase search performance and scalability as cache can then be generated based on mostly searched shared.  https://www.elastic.co/guide/en/elasticsearch/reference/current/scalability.html

4. "hits" : value indicates the number of hits that match and relation indicates whether the value is accurate (eq) or a lower bound (gte). Here "eq" would mean exact number of document matches, "gte" would mean there are more partial matches other than exact matches (interpret as "at-least" n exact matches). Problem in submitted query is when relation is "lte", it means no exact match. 

5. {profile} — to be continued tommorrow.



## URL Params can be used to create a single line command for outputting performance indicators.
```
GET /security-auditlog-*/_search/?format=json&pretty=true&filter_path=took,hits.hits._id,hits.hits._score

{

  "profile": true,

  "query": {

    "match_all": {}

  }

}
```


## Troubleshooting - when was index/shard created ? - 
```
GET /security-auditlog-*/_settings/?flat_settings=true
```

## Troubleshoot - show stack trace of errors -
```
POST /security-auditlog-*/_search?size=kingju&error_trace=true
```

## Next, we need to finalise which parameters will be used 

```
GET /auditd/_search/?filter_path=took,timed_out,_shards.total,_shards.skipped,_shards.failed,hits.total.relation,hits.total.value,profile.shards.id,profile.shards.searches.collector.name,profile.shards.searches.collector.reason,profile.shards.searches.collector.time_in_nanos,profile.shards.searches.query.type,profile.shards.searches.query.time_in_nanos,profile.shards.searches.query.breakdown.match_count,profile.shards.searches.query.breakdown.score_count,profile.shards.searches.query.breakdown.score,profile.shards.searches.query.children.type,profile.shards.searches.query.children.description,profile.shards.searches.query.children.time_in_nanos&format=yaml
{
  "profile": true,
  "query": {
    "match_all": {}
  }
}
```
## Additional elasticsearch endpoints which show perfromance stats.
```
GET /_cat/nodes?v&h=*node*,search*,http*, name*
GET /_cat/nodes?v&h=heap.max,search.query_total,name, search.fetch_time
GET /_cat/thread_pool/search?v&h=node_name,name,active,rejected,completed
GET /_nodes/stats?groups=_all
GET /_nodes/stats/indices/query_cache
GET /_nodes/stats/indices/search?pretty
GET /.opendistro-alerting-alerts/_stats
GET /_nodes/stats/ingest?filter_path=nodes.*.ingest
GET /auditd/_stats?pretty=true
GET /_cluster/health?pretty=true
GET /_cat/health
GET /_cluster/state?flat_settings=true
GET /_nodes/stats
```

## If opendistro is being used for alerting, then this config lists all detections.
```
GET /.opendistro-alerting-config?flat_settings=true
```
