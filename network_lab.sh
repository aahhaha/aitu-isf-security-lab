#!/usr/bin/env bash
# Execute only on an ephemeral Linux CI runner. All firewall changes stay inside a new router namespace.
set -euo pipefail
[[ "$(uname -s)" == Linux && "$EUID" == 0 ]] || { echo 'Requires a disposable Linux runner and root'; exit 2; }
prefix="cq-lab-$$"
client="$prefix-c"; router="$prefix-r"; server="$prefix-s"
cleanup() {
 for ns in "$client" "$router" "$server"; do
  ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null || true
  ip netns del "$ns" 2>/dev/null || true
 done
}
trap cleanup EXIT
for ns in "$client" "$router" "$server"; do ip netns add "$ns"; ip -n "$ns" link set lo up; done
ip link add cq-c type veth peer name cq-rc
ip link add cq-s type veth peer name cq-rs
ip link set cq-c netns "$client"; ip link set cq-rc netns "$router"
ip link set cq-s netns "$server"; ip link set cq-rs netns "$router"
ip -n "$client" link set cq-c name eth0
ip -n "$server" link set cq-s name eth0
for iface in cq-rc cq-rs; do ip -n "$router" link set "$iface" up; done
ip -n "$client" link set eth0 up; ip -n "$server" link set eth0 up
ip -n "$client" link add link eth0 name eth0.10 type vlan id 10
ip -n "$router" link add link cq-rc name rc.10 type vlan id 10
ip -n "$server" link add link eth0 name eth0.20 type vlan id 20
ip -n "$router" link add link cq-rs name rs.20 type vlan id 20
ip -n "$client" addr add 10.10.10.2/24 dev eth0.10; ip -n "$client" link set eth0.10 up
ip -n "$router" addr add 10.10.10.1/24 dev rc.10; ip -n "$router" link set rc.10 up
ip -n "$server" addr add 10.20.20.2/24 dev eth0.20; ip -n "$server" link set eth0.20 up
ip -n "$router" addr add 10.20.20.1/24 dev rs.20; ip -n "$router" link set rs.20 up
ip -n "$client" route add default via 10.10.10.1
ip -n "$server" route add default via 10.20.20.1
ip netns exec "$router" sysctl -qw net.ipv4.ip_forward=1
ip netns exec "$router" iptables -P FORWARD DROP
ip netns exec "$router" iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip netns exec "$router" iptables -A FORWARD -s 10.10.10.0/24 -d 10.20.20.2 -p tcp --dport 8443 -j ACCEPT
ip netns exec "$router" iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o rs.20 -j MASQUERADE
ip netns exec "$server" python3 -u -c '
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import threading
class H(BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200);self.end_headers();self.wfile.write(self.client_address[0].encode())
for port in [8080,8443]:threading.Thread(target=ThreadingHTTPServer(("0.0.0.0",port),H).serve_forever,daemon=True).start()
threading.Event().wait()
' &
for _ in $(seq 1 30); do
 if ip netns exec "$server" python3 -c 'import socket;s=socket.create_connection(("127.0.0.1",8443),timeout=.2);s.close()' 2>/dev/null; then break; fi
 sleep .1
done
mkdir -p reports
ip netns exec "$server" python3 -c 'import socket;s=socket.create_connection(("127.0.0.1",8080),timeout=2);s.close()'
ip netns exec "$client" python3 - <<'PY' > reports/network.json
import socket,urllib.request,json
from datetime import datetime,timezone
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
peer=opener.open('http://10.20.20.2:8443',timeout=3).read().decode()
assert peer=='10.20.20.1',peer
blocked=False
try:socket.create_connection(('10.20.20.2',8080),timeout=1)
except (TimeoutError,OSError):blocked=True
assert blocked,'ACL did not block port 8080'
print(json.dumps({'recorded_at_utc':datetime.now(timezone.utc).isoformat(),'environment':'three isolated Linux network namespaces','VLANs':[10,20],'allowed_port':8443,'blocked_port':8080,'observed_NAT_source':peer,'passed':True,'protocol_note':'HTTP for network reachability; TLS is tested separately'},indent=2))
PY
cat reports/network.json
