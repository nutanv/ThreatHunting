# Exfil Notes - DateRange - 30Apr2020 to 18May2020.

https://confluence.atlassian.com/bitbucketserverkb/how-to-read-the-bitbucket-server-log-formats-779171668.html


## BitBucket SSH Auth Events -
```
index=atlassian_bitbucket sourcetype="bitbucket:audit" “SshAuthenticationSuccessEvent" earliest=5/6/2020:00:00:00 latest=8/12/2020:00:00:00
| rex field=_raw "(?<ip_address>[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\s\|\s(?<event_name>\w+)\s\|\s(?<user>\w+)\s\|\s(?<epoc_time>\d+)\s\|\s(?<user_presented>\w+)\s\|\s(?<msg>\{.*\})\s\|\s(?<bb_request_id>\@\w*)\s\|\s(?<sess_id>\w+)"
| table ip_address event_name user epoc_time user_presented msg bb_request_id sess_id
| stats values(msg) values(user_presented) count by user
| sort -count
```

## BitBucket/Git Repo Clone/Pull/Fork Events - 
```
index=atlassian_bitbucket sourcetype="bitbucket:audit" ("RepositoryCloneEvent" OR "RepositoryForkedEvent" OR "RepositoryPullEvent”) earliest=5/6/2020:00:00:00 latest=8/12/2020:00:00:00
| rex field=_raw "(?<ip_address>[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\s\|\s(?<event_name>\w+)\s\|\s(?<user>\w+)\s\|\s(?<epoc_time>\d+)\s\|\s(?<repo_cloned>.[^\s\|]+)\s\|\s(?<bb_msg>.)\s\|\s(?<bb_req_params>.[^\s\|]+)\s\|\s(?<bb_ses_id>.+)" 
| eval readable_time = strftime(epoc_time,"%Y-%m-%d %Z") 
| table ip_address event_name user epoc_time readable_time repo_cloned bb_msg bb_req_params bb_ses_id 
| stats values(event_name) dc(bb_ses_id) count by repo_cloned, user
| sort -count

----

index=atlassian_bitbucket sourcetype="bitbucket:audit" jastrang ("RepositoryCloneEvent" OR "RepositoryForkedEvent" OR "RepositoryPullEvent”) earliest=5/6/2020:00:00:00 latest=8/12/2020:00:00:00
| rex field=_raw "(?<ip_address>[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\s\|\s(?<event_name>\w+)\s\|\s(?<user>\w+)\s\|\s(?<epoc_time>\d+)\s\|\s(?<repo_cloned>.[^\s\|]+)\s\|\s(?<bb_msg>.)\s\|\s(?<bb_req_params>.[^\s\|]+)\s\|\s(?<bb_ses_id>.+)" 
| eval readable_time = strftime(epoc_time,"%F %H:%M:%S") 
| table ip_address event_name user epoc_time readable_time repo_cloned bb_msg bb_req_params bb_ses_id 
| stats values(event_name) values(repo_cloned) dc(repo_cloned) dc(bb_ses_id) values(readable_time) count by user
| sort -count
```
## BitBucket Access Logs -
```
index=atlassian_bitbucket sourcetype=bitbucket:access http earliest=5/6/2020:00:00:00 latest=8/12/2020:00:00:00
| rex field=_raw  "(?<ip_address>[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})(?<dunno>.[^\s\|]+)\s\|\s(?<proto>\w+)\s\|\s(?<bb_req_params>[^\s\|]+)\s\|\s(?<bb_read_username>[^\s\|]+)\s\|\s(?<bb_time>[^\|]+)\s\|\s\"(?<bb_action>.[^\|]*)\s\|\s(?<bb_req>.[^\s]*)\s\"(?<bb_user_agent>.[^\"]*)\"\s\|\s(?<bbs_code>\d+)\s\|\s(?<bb_bytes_read>\d+)\s\|\s(?<bytes_write>\w+)\s\|\s(?<bb_label>[^\s\|]+)\s\|\s(?<bb_response_time>\d)\s\|\s(?<bb_sess_id>\w+)\s(?<rest_of_it>.*)"
| table ip_address dunno proto bb_req_params bb_read_username bb_time bb_action bb_req bb_user_agent bbs_code bb_bytes_read bytes_write bb_label bb_response_time bb_sess_id rest_of_it
```

## BitBucket GitAccess Logs - 
```
index=atlassian_bitbucket sourcetype=bitbucket:access ssh earliest=5/6/2020:00:00:00 latest=8/12/2020:00:00:00
| rex field=_raw  "(?<ip_address>[^\s\|]+)\s\|(?<proto>.[^\s\|]+)\s\|(?<bb_req_params>.[^\s\|]+)\s\|(?<bb_read_username>.[^\s\|]+)\s\|(?<bb_time>[^\|]+)\s\|\s(?<git_ssh_cmd>[^\|]+)\s\|(?<git_ssh_version>[^\|]+)\s\|(?<git_exit_code>[^\|]+)\s\|(?<git_read>[^\|]+)\s\|(?<git_write>[^\|]+)\s\|(?<git_params>[^\|]+)\s\|(?<git_response_time>[^\|]+)\s\|(?<git_session_id>[^\|]+)\s(?<everything_else>.*)"
| table ip_address proto bb_req_params bb_read_username bb_time git_ssh_cmd git_ssh_version git_exit_code git_read git_write git_params git_response_time git_session_id everything_else
```

# Artifactory - https://www.jfrog.com/confluence/display/JFROG/Logging

## AccessLogs parsed 
```
index="artifactory" source="/var/opt/jfrog/artifactory/logs/access.log"  earliest=5/6/2020:00:00:00 latest=8/12/2020:00:00:00
| rex field=_raw  "(?<date_utc>[^\,]+)\,(?<traceId>\d+)\s\[(?<action>[^\]]+)\]\s(?<artifact>[^\s]+)\s\s(?<msg_optional>[^\:]+)\:\s(?<username>\w+)\s\/\s(?<clientIP>.*)"
| table date_utc traceId action artifact msg_optional username clientIP
| stats count by username action
| sort - count
```

## Request Logs Parsed
```
index="artifactory" source="/var/opt/jfrog/artifactory/logs/request.log" earliest=5/6/2020:00:00:00 latest=8/12/2020:00:00:00
| rex field=_raw "(?<ts_utc>[^\|]+)\|(?<traceID>[^\|]+)\|(?<action>[^\|]+)\|(?<cip>[^\|]+)\|(?<user>[^\|]+)\|(?<method>[^\|]+)\|(?<path>[^\|]+)\|(?<version>[^\|]+)\|(?<sc>[^\|]+)\|(?<content_length>[^\|]+)"
| table ts_utc traceID action cip user method path version sc content_length
```

## EventLog Parsed -
```
index="artifactory" earliest=5/6/2020:00:00:00 latest=8/12/2020:00:00:00 sourcetype="artifactory:event"
| rex field=_raw  "(?<ts_utc>[^\|]+)\|(?<event_name>[^\|]+)\|(?<artifact>.*)"
| table ts_utc event_name artifact
```



