# Time period -eg 60 minutes
# Abuse of Kerberos Tickets - Kerberosting:
Adjust variables below and whitelist any users that are service accounts that are noisey. This is for any encryption type which allows for failures.
```
index=winevent_sec EventCode=4769 Ticket_Options=0x40810000 Service_Name!="*$" Service_Name!="krbtgt" Account_Name!="*$@*" 
| dedup Service_Name 
| stats count by user 
| where count>X (where x is a good baseline)
```
## Attacker trying to harvest kerberos tickets issued for weaker encryption like RC4.– this is since they crack faster so are generally the hackers choice.
```
index=winevent_sec EventCode=4769 Ticket_Options=0x40810000 Ticket_Encryption_Type=0x17 Service_Name!="*$" Service_Name!="krbtgt" Account_Name!="*$@*" 
| dedup Service_Name 
| stats count by user 
| where count>X (where x is a good baseline)
```

# Attacker choosing to connect to abnormal domains.
### DGA Detection - DNS High Entropy Domain names
```
| tstats count(DNS.dest) AS "Count of dest" from datamodel=Network_Resolution where (nodename = DNS) NOT DNS.query IN ("**X.com*", "**Y.COM*", "**Z.COM*",) groupby DNS.query, DNS.src prestats=true 
| stats dedup_splitvals=t count(DNS.dest) AS "CountD" by DNS.query, DNS.src 
| sort limit=0 DNS.query 
| rename DNS.query AS query DNS.src AS src 
| fillnull "CountD" 
| fields query, "CountD", src, - _span  
| where CountD=1 
| eval list="mozilla" 
| `ut_parse(query, list)` 
| `ut_shannon(ut_domain)` 
| where ut_shannon>3.5 
| lookup ad_assets_lookup_tracker.csv ip as src OUTPUT dns as src-resolved
| table ut_shannon, query, src, src-resolved 
| sort ut_shannon desc
```
### DNS Beaconing Queries by connection count and deviation
```
index=*dns*
| eval current_time=_time
| sort 0 + current_time
| streamstats global=f window=2 current=f last(current_time) AS previous_time by host, query
| eval diff_time=current_time-previous_time
| eventstats count, stdev(diff_time) AS std by host, query
| where std<5 AND count>50
| stats count AS conn_count, dc(host) AS unique_sources, values(std) AS diff_deviation, values(category) AS category BY query
```
# Beaconing Queries by time delta

```
index=*dns*
| fields host, query, _time 
| fields - _raw 
| sort 0 query,host,-_time
| streamstats current=f window=1 first(_time) as next_query by query, host
| eval delta=round(abs(next_query-_time),0)
| search delta>0 
| search  query!="None"
| stats count as query_count dc(delta) as delta_dc by query
| eval num_requests_per_time_delta=query_count/delta_dc
| where num_requests_per_time_delta >= 5
| sort 500 - query_count
| table query num_requests_per_time_delta query_count
```

# C2 traffic to random hosts on random ports.
## Using Splunk Machine Learning Toolkit to show 'weird' destination ports - limited time lengths available depending on your result numbers.
This will attempt to show anomalous destination ports and remove internal destination traffic from the results.
```
| tstats count AS "Count of All Traffic" from datamodel=Network_Traffic where (nodename = All_Traffic) groupby All_Traffic.user, All_Traffic.dest_ip, All_Traffic.src_ip, All_Traffic.dest_port, All_Traffic.src_port prestats=true 
| stats dedup_splitvals=t count AS "Count of All Traffic" by All_Traffic.user, All_Traffic.dest_ip, All_Traffic.src_ip, All_Traffic.dest_port, All_Traffic.src_port 
| rename All_Traffic.user AS user All_Traffic.dest_ip AS dest_ip All_Traffic.src_ip AS src_ip All_Traffic.dest_port AS dest_port All_Traffic.src_port AS src_port 
| fillnull "Count of All Traffic" 
| fields src_ip,src_port, user, dest_ip, dest_port, "Count of All Traffic" 
| where (NOT cidrmatch("10.0.0.0/8",dest_ip) AND NOT cidrmatch("172.16.0.0/12",dest_ip) AND NOT cidrmatch("192.168.0.0/16",dest_ip) AND NOT cidrmatch("10.blah.blah.blah/24",src_ip) AND cidrmatch("10.0.0.0/8",src_ip)) 
| anomalydetection dest_port 
| sort - dest_port
```
## Using Splunk Machine Learning Toolkit to show 'weird' connection pairs (rare) - limited time lengths available depending on your result numbers.
```
| tstats count AS "Count of All Traffic" from datamodel=Network_Traffic where (nodename = All_Traffic) groupby All_Traffic.user, All_Traffic.dest_ip, All_Traffic.src_ip, All_Traffic.dest_port, All_Traffic.src_port prestats=true 
| stats dedup_splitvals=t count AS "Count of All Traffic" by All_Traffic.user, All_Traffic.dest_ip, All_Traffic.src_ip, All_Traffic.dest_port, All_Traffic.src_port 
| rename All_Traffic.user AS user All_Traffic.dest_ip AS dest_ip All_Traffic.src_ip AS src_ip All_Traffic.dest_port AS dest_port All_Traffic.src_port AS src_port 
| fillnull "Count of All Traffic" 
| fields src_ip,src_port, user, dest_ip, dest_port, "Count of All Traffic" 
| where (NOT cidrmatch("10.0.0.0/8",dest_ip) AND NOT cidrmatch("172.16.0.0/12",dest_ip) AND NOT cidrmatch("192.168.0.0/16",dest_ip) AND NOT cidrmatch("10.blah.blah.blah/24",src_ip) AND cidrmatch("10.0.0.0/8",src_ip)) 
| anomalydetection dest_ip 
| sort - dest_port
```
## Using Splunk Machine Learning Toolkit to show 'weird' outbound http user agent strings. Filtered out Google (try leaving it in and see what happens!).
```
| tstats count AS "Count of Web" from datamodel=Web where (nodename = Web) (Web.src="10*") (Web.dest!=*google*) groupby Web.http_user_agent, Web.dest, Web.url, Web.src prestats=true 
| stats dedup_splitvals=t count AS "Count of Web" by Web.http_user_agent, Web.dest, Web.url, Web.src 
| sort limit=0 Web.http_user_agent 
| fields - _span 
| rename Web.http_user_agent AS http_user_agent Web.dest AS dest Web.url AS url Web.src AS src 
| fillnull "Count of Web" 
| fields http_user_agent, dest, url, src, "Count of Web" 
| anomalydetection http_user_agent 
| sort + "Count of Web"
```
# Attacker could exfil OR download files with custom (wiered) extensions 
### Useful in situations where there isn't implemented or effective internet whitelisting. Detects file extensions that have been accessed on sites that the web proxy has determined are uncategorised or new/unknown. 
### Needs whitelisting a few. Had to remove a few extensions due to false-positive count being way too high.
```
| tstats count AS "Count of Web" from datamodel=Web where (nodename = Web) (Web.url!="whitelist1" AND Web.url!="whitelist2etc" AND Web.url="/*.com" OR Web.url="*.SCF" OR Web.url="*.INF" OR Web.url="*.LNK" OR Web.url="*.PS1" OR Web.url="*.PS1XML" OR Web.url="*.PS2" OR Web.url="*.PS2XML" OR Web.url="*.PSC1" OR Web.url="*.PSC2" OR Web.url="*.JSE" OR Web.url="*.VBE" OR Web.url="*.CMD" OR Web.url="*.GADGET" OR Web.url="*.MSP" OR Web.url="*.MSI" OR Web.url="*.DOC" OR Web.url="*.DOCX" OR Web.url="*.DOCM" OR Web.url="*.exe" OR Web.url="*.HTA"  OR Web.url="*.JAR" OR Web.url="*.VBS" OR Web.url="*.VB" OR Web.url="*.PDF" OR Web.url="*.SFX" OR Web.url="*.BAT" OR Web.url="*.DLL" OR Web.url="*.TMP" OR Web.url="*.py") (Web.category=unknown OR Web.category=uncategorized OR Web.category="Newly Registered Websites") groupby _time, host, Web.url, Web.category, Web.user, Web.http_content_type, Web.src,  prestats=true 
| stats dedup_splitvals=t count AS "Count of Web" by _time, Web.src,  Web.url, Web.category, Web.user, Web.http_content_type 
| sort limit=0 _time 
| rename Web.url AS url Web.category AS category Web.user AS user Web.http_content_type AS http_content_type Web.src AS src 
| fillnull "Count of Web" 
| dedup url
| fields _time, url, src,  category, user, http_content_type, "Count of Web"
```

# Generic Query to lookup against a static list of interest. 
[| tstats count from datamodel=egress_proxy where (nodename = pax1) (Web.category=unknown OR Web.category=uncategorized OR Web.category="Newly Registered Websites") prestats=true groupby _time Web.url Web.dest
| fields Web.url Web.dest _time
| search [ | inputlookup IOC_List_Hash_IP_Port_URLs.csv | fields http.url]
| stats count values(http.url) by http.dest]
