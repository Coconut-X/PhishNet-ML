#!/bin/sh
set -e

#env vars from the host: TARGET_IPS (comma separated), TARGET_PORT

#firewall first. only the target ip is allowed out, everything else gets rejected
#(reject instead of drop so blocked stuff fails fast and doesnt hang until timeout)
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
for ip in $(echo "$TARGET_IPS" | tr ',' ' '); do
    iptables -A OUTPUT -p tcp -d "$ip" -m multiport --dports "80,443,$TARGET_PORT" -j ACCEPT
done
iptables -A OUTPUT -j REJECT
iptables -P OUTPUT DROP

#then run the command (fetch.py by default, see CMD in the Dockerfile) as a normal user
#with no capabilities at all, so the browser cant change the rules we just set
#(no NET_ADMIN) or get any new privileges
exec setpriv --reuid=pwuser --regid=pwuser --init-groups \
    --inh-caps=-all --bounding-set=-all --no-new-privs \
    "$@"
