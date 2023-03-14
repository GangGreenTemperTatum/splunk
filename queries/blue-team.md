## DDOS Detection:

```
index=WAF OR index=Firewall
|bin _time span=15m
|fields src_port,src,dest
|stats count,dc(src) as src_count , dc(dest) as dest_count by src_port,_time,src,dest
|eval First_Factor=src_count/dest_count 
|eval Final_Factor=First_Factor+count |eval ddoscount=count 
|search Final_Factor > 10
|eval msg="DoS Attack "."count:".count."  from ".src_count. " same src_port:".src_port." on ". dest_count. " servers"
|fields msg ddoscount count src_port,src,dest  | timechart values(ddoscount) by msg useother=false

index=WAF OR index=Firewall
|bin _time span=5m
|fields src_port,src,dest
|stats count,dc(src) as src_count , dc(dest) as dest_count by src_port,_time,src,dest
|eval First_Factor=src_count/dest_count 
|eval Final_Factor=First_Factor+count 
|search Final_Factor > 10
|eval msg=" DDoS Attack detected. "."count:".count."  from ".src_count. " distict sources with same src_port:".src_port." on ". dest_count. " servers"
|fields msg count src_port,src,dest  |sort -count
```
