# Networking ReactOS in v86

The browser cannot open arbitrary TCP, UDP, or raw Ethernet sockets. v86 works
around that limitation by emulating a network card in the guest and forwarding
its traffic to a proxy over WebSocket.

For ReactOS, use v86's `ne2k` device. It emulates an NE2000/RTL8390-compatible
PCI adapter, for which ReactOS has a suitable driver. Do not select the v86
VirtIO network device unless a compatible ReactOS driver has been installed in
the image first.

There are two useful proxy configurations:

| Backend | Guest traffic | Server requirements | Recommended use |
| --- | --- | --- | --- |
| WISP | Outbound TCP; synthetic DHCP, DNS, NTP, ping, and related services | Unprivileged Node.js service behind a TLS reverse proxy | Web browsing, HTTP(S), and other outbound TCP clients |
| WebSocket Ethernet (`wsproxy`) | Raw Ethernet, including TCP and UDP | TAP device, DHCP, DNS, forwarding, NAT, and usually a privileged container | Applications that require arbitrary UDP or fuller network emulation |

## Important WISP UDP limitation

The WISP protocol and current `wisp-js` server support both TCP and UDP stream
types. However, the WISP backend in the v86 version used by this page does not
forward arbitrary guest UDP streams. It forwards TCP and locally emulates the
small set of UDP-based services required for normal configuration, including
DHCP, DNS through DNS-over-HTTPS, and NTP.

Consequently:

- DNS, DHCP, ping, NTP, HTTP, HTTPS, and outbound TCP applications can work
  through WISP.
- A ReactOS program sending arbitrary UDP datagrams to an Internet server will
  not work through the v86 WISP backend.
- Use the raw WebSocket Ethernet backend described later if arbitrary TCP and
  UDP are both required.

## Option 1: WISP for outbound TCP

WISP is the simplest and safest starting point. The proxy does not need root,
TAP devices, IP forwarding, or direct access to Ethernet frames.

### 1. Install the WISP server

Use the maintained `@mercuryworkshop/wisp-js` package. The older
`wisp-server-node` package is archived and explicitly deprecated for security
and stability reasons.

On a server with a supported Node.js and npm installation:

```sh
sudo install -d -o "$USER" -g "$USER" /opt/r2-wisp
cd /opt/r2-wisp
npm init -y
npm install @mercuryworkshop/wisp-js
```

For an initial test, listen only on localhost:

```sh
npx wisp-js-server \
  --host 127.0.0.1 \
  --port 5001 \
  --logging INFO \
  --options '{"allow_private_ips":false,"allow_loopback_ips":false,"allow_direct_ip":false,"stream_limit_total":64,"stream_limit_per_host":8,"port_whitelist":[80,443]}'
```

This example intentionally permits only web ports. Adjust `port_whitelist` if
the guest needs other outbound TCP services. Avoid an unrestricted public
relay: it can be abused as an anonymous proxy and can consume arbitrary amounts
of bandwidth and file descriptors.

For a long-running installation, create a dedicated unprivileged account and a
service managed by the host's init system. Pin and review the npm package
version when deploying rather than updating production automatically.

### 2. Put the WISP server behind TLS

A page served over HTTPS must connect to a secure WebSocket endpoint. In v86,
the secure WISP URL uses the `wisps://` scheme. Terminate TLS in nginx, Caddy, or
another reverse proxy and forward WebSocket upgrades to `127.0.0.1:5001`.

Example nginx location inside an HTTPS virtual host:

```nginx
location /wisp/ {
    proxy_pass http://127.0.0.1:5001;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_read_timeout 1d;
    proxy_send_timeout 1d;
}
```

The public endpoint in this example is:

```text
wisps://reactos.example.org/wisp/
```

Use `wisp://` only for local HTTP development. Browsers will block an insecure
WebSocket connection made by an HTTPS page as mixed content.

### 3. Configure v86 with NE2000 and WISP

Add a `net_device` member to the object passed to `new V86(...)`:

```javascript
net_device: {
  type: "ne2k",
  relay_url: "wisps://reactos.example.org/wisp/",
  router_ip: "192.168.86.1",
  vm_ip: "192.168.86.100",
  masquerade: true,
  dns_method: "doh",
  doh_server: "cloudflare-dns.com"
},
```

The important settings are:

- `type: "ne2k"` exposes the compatible virtual network adapter to ReactOS.
- `relay_url` selects WISP and identifies the proxy endpoint.
- `vm_ip` is the address offered to ReactOS by v86's built-in DHCP service.
- `router_ip` is the synthetic gateway presented to ReactOS.
- `masquerade` makes destinations outside the virtual subnet reachable.
- `dns_method: "doh"` lets v86 resolve guest DNS requests using the browser's
  HTTPS facilities, because general guest UDP is not forwarded by WISP.

If the page and relay share a hostname, nginx can serve the static page and
proxy `/wisp/` from the same HTTPS virtual host.

### 4. Configure and test ReactOS

ReactOS should detect an NE2000/RTL8029-style PCI adapter. If it asks for a
driver, let its hardware wizard search the installed ReactOS driver set. Then
configure the adapter for automatic addressing (DHCP).

From a ReactOS command prompt:

```bat
ipconfig /all
ping 192.168.86.1
ping example.com
```

Expected results include an address such as `192.168.86.100`, a gateway and DNS
server of `192.168.86.1`, and successful name resolution. A successful ping
checks v86's synthetic ICMP handling; it does not prove arbitrary ICMP access to
the remote host.

Test actual TCP with an HTTP client or browser. HTTPS connectivity can still
fail because the browser and TLS libraries shipped with ReactOS may not support
the algorithms or certificate chains used by modern sites. That is separate
from the v86 network connection.

When debugging, inspect all three layers:

1. ReactOS Device Manager: the NE2000 adapter must exist without an error icon.
2. ReactOS `ipconfig /all`: DHCP must assign the virtual address and gateway.
3. Browser developer tools and WISP logs: the WebSocket upgrade must succeed and
   the requested destination must pass the server restrictions.

Common browser-side failures are an invalid certificate, an HTTPS page using a
`wisp://` rather than `wisps://` URL, a reverse proxy that does not forward the
WebSocket `Upgrade` header, or a CDN that imposes a short WebSocket timeout.

## Option 2: raw Ethernet for TCP and UDP

Use v86's `wsproxy` backend when ReactOS applications need arbitrary UDP. This
backend forwards complete Ethernet frames over WebSocket. The relay host must
provide a TAP interface, DHCP, DNS, routing, and NAT.

The reference `websockproxy` Docker image provides these pieces for testing:

```sh
docker run --detach \
  --name r2-reactos-relay \
  --privileged \
  --publish 127.0.0.1:8080:80 \
  benjamincburns/jor1k-relay:latest
```

The container is privileged because it creates a TAP interface and configures
IP forwarding, iptables masquerading, and dnsmasq. Binding it to localhost keeps
the unencrypted relay port from being exposed directly. Put it behind an HTTPS
reverse proxy with WebSocket upgrade support, as with WISP.

For example, proxy `/relay/` to `http://127.0.0.1:8080/`, then configure v86:

```javascript
net_device: {
  type: "ne2k",
  relay_url: "wss://reactos.example.org/relay/"
},
```

Notice the scheme difference:

- `wisps://` selects the WISP transport backend.
- `wss://` selects the raw WebSocket Ethernet backend.

With raw Ethernet, addressing comes from the relay's DHCP service rather than
v86's WISP DHCP implementation. Verify it using `ipconfig /all`, then test TCP,
DNS, and an application that uses UDP.

### Raw relay security

A raw Ethernet relay has a substantially larger security surface than WISP:

- A privileged container can affect host networking. Prefer a dedicated VM or
  isolated server rather than a general-purpose host.
- Block access from the relay network to the host, cloud metadata addresses,
  loopback, RFC1918/private networks, and administrative subnets unless access
  is explicitly required.
- Apply outbound firewall rules, connection limits, bandwidth quotas, and log
  rotation.
- A simple shared TAP relay can place unrelated browser guests on the same
  layer-2 network. They may be able to scan or attack one another. Use a relay
  that isolates clients, or run separate relay instances for untrusted users.
- Do not expose the relay's plain `ws://` listener to the Internet. Publish only
  the TLS reverse-proxy endpoint.
- The reference container is useful for validation, but its dependencies,
  privileges, firewall behavior, and maintenance status must be reviewed before
  production deployment.

The v86 networking documentation also lists alternatives such as `wsnic` and
`RootlessRelay`, which may offer better client isolation or avoid TUN/TAP
privileges. Evaluate them against the required TCP, UDP, DHCP, NAT, and security
properties before choosing a production relay.

## Choosing a backend

Start with WISP when the goal is to browse sites, download files, or connect to
outbound TCP services. It is simpler to deploy and easier to restrict.

Choose raw WebSocket Ethernet only when an application genuinely needs general
UDP, broadcast/multicast behavior, guest-to-guest networking, or protocols that
the WISP backend cannot translate. The extra behavior comes with significantly
more operational and security work.

## References

- [v86 networking guide](https://github.com/copy/v86/blob/master/docs/networking.md)
- [v86 API types and `net_device` options](https://github.com/copy/v86/blob/master/v86.d.ts)
- [Maintained `wisp-js` client/server](https://github.com/MercuryWorkshop/wisp-js)
- [Reference raw Ethernet `websockproxy`](https://github.com/benjamincburns/websockproxy)
- [WISP protocol](https://github.com/MercuryWorkshop/wisp-protocol)
