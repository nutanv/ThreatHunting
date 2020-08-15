## Below is a list of interesting snort signatures, which could be used for hunting.
| brief | signature|
|---|---|
|Unicode abuse - APT34 | alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Abusing URLs with Unicode 0x2028 Line Separator"; flow:to_server,established; content:"%E2%80%A8"; http_raw_uri:; reference:cve,2020-12397; sid:1; gid:1; rev:1;)|
