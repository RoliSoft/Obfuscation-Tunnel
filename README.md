# Obfuscation Tunnel

The purpose of this project is two-fold:

* Implement a high-performance and low-overhead UDP-to-UDP tunnel, which has support for encrypting/obfuscating the encapsulated traffic in order to avoid fingerprinting. (Initially developed specifically for masking Wireguard headers.)
* Implement a tunnel which can change the transport protocol from UDP to TCP or ICMP(/v6) in order to evade firewalls which block non-fingerprintable/whitelisted UDP packets, or just UDP traffic outright.

## Usage

```
usage: ./tunnel -l proto:addr:port -r proto:addr:port [args]
arguments:

   -l endpoint  Local listening protocol, address and port.
                  Example: tcp:127.0.0.1:80 / icmp6:[::1]
                  Supported protocols: udp, dtls, tcp, tls, icmp, imcp6.
   -r endpoint  Remote host to tunnel packets to.
   -o [mode]    Enable packet obfuscation. Possible values:
                  header - Simple generic header obfuscation (Default)
                  xor - XOR packet obfuscation with rolling key
   -k key       Specifies a key for the obfuscator module.
   -m mode      Enable protocol imitator. Possible values:
                  dns_client - Send data as A queries to remote
                  dns_server - Reply to A queries on local
                  http_ws_client - Masquarade as HTTP WebSocket stream
                  http_ws_server - Accept data in HTTP WebSocket streams
                  socks5:<addr>:<port> - Connect through a SOCKSv5 proxy
   -s           Disable multithreading, multiplex sockets instead.
   -v           Detailed logging at the expense of decreased throughput.
   -h, --help   Displays this message.

TCP-specific arguments:

   -e           Type of encoding to use for the length header:
                  v - 7-bit encoded variable-length header (Default)
                  s - 2-byte unsigned short
                  n - None (Not recommended)

ICMP/ICMPv6-specific arguments:

   -p [if]      Use PCAP for inbound, highly recommended.
                  Optional value, defaults to default gateway otherwise.
   -x           Expect identifier and sequence randomization.
                  Not recommended, see documentation for pros and cons.

DNS-specific arguments:

   -f           Base32-encode data and fragment labels on 60-byte boundaries.
   -d domain    Optional domain name to act as the authoritative resolver for.

(D)TLS-specific arguments:

   --tls-no-verify  Ignore certificate validation errors of remote server.
   --tls-ca-bundle  Path to CA bundle, if not found automatically by OpenSSL.
   --tls-cert       Path to SSL certificate file in PEM format.
                      Optional, otherwise it will be auto-generated and self-signed.
   --tls-key        Path to SSL private key file in PEM format.
```

Example for UDP-to-UDP tunnel:

```
server$ ./tunnel -l udp:0.0.0.0:80 -r udp:engage.cloudflareclient.com:2408
client$ ./tunnel -r udp:server:80 -l udp:127.0.0.1:2408
```

For this example, any packet sent to 127.0.0.1:2408 will be forwarded to server:80, which will further forward it to engage.cloudflareclient.com:2408. Replies will be forwarded backwards through the chain to the last client which sent a valid UDP packet. In essence, the only modification you will need to do to your Wireguard config to go through the tunnel is to replace:

```
[Peer]
Endpoint = engage.cloudflareclient.com:2408
```

With the following:

```
[Peer]
Endpoint = 127.0.0.1:2408
```

Note that while the documentation for this application largely talks in terms of Wireguard examples, the application itself is completely protocol-agnostic, and has nothing to do with Wireguard directly.

## Building

To compile and run the application, you must first install the dependencies, which can be done with:

-   Debian/Ubuntu/Kali:

    ```
     apt install build-essential libpcap-dev
    ```

-   RHEL/CentOS/Fedora:
    
    ```
     yum install gcc make libpcap-devel
    ```

-   macOS: (with  [Homebrew](http://brew.sh/))
    
    ```
     xcode-select --install && brew install libpcap
    ```

After the dependencies have been satisfied, you can clone the repository and make it:

```
git clone https://github.com/RoliSoft/Obfuscation-Tunnel.git
cd Obfuscation-Tunnel
make
```

If you wish to build without libpcap:

* Skip the installation of the `libpcap` dependency.
* Open the `Makefile` file in your editor,
* Find the `CXXFLAGS` line (should be the first),
* Replace the flags `-DHAVE_PCAP=1 -lpcap` with `-DHAVE_PCAP=0`

## Tunneling VPN traffic

If you are preparing to tunnel VPN traffic, it is very important to make sure that the application can communicate with the default gateway, and once the VPN connects, it will not be redirected to the VPN. If your VPN will try to redirect all traffic (0.0.0.0/0) or the redirected traffic overlaps with the location of the gateway server, you will notice that the connection drops after the initial handshake, once the VPN client sets up the routes and unknowingly hijacks the tunnel's communication.

In order to do this, you can set a static route to the gateway server to be always via the default network interface on your client. However, as a side-effect, any other traffic to the IP address on which your gateway tunnel resides will not be tunneled through the VPN, so make sure you account for this, if you use it for other services.

If you are using ICMPv6, make sure to adapt the commands for IPv6 and set the static route to the IPv6 address of your gateway server.

### Linux

First check the default gateway before the VPN is connected:

```
$ route
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
default         192.168.0.1     0.0.0.0         UG    0      0        0 eth0
```

Knowing the network interface of the default gateway (`eth0` in this example), set a static route to your gateway tunnel server (`123.45.67.89` in this example):

```
sudo ip route add 123.45.67.89/32 dev eth0
```

This will make sure your tunnel traffic will not be hijacked once the VPN is connected.

### macOS

First check the default gateway before the VPN is connected:

```
$ netstat -nr
Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            172.20.10.1        UGSc         en4
```

Knowing the IP address of the default gateway (`172.20.10.1` in this example), set a static route to your gateway tunnel server (`123.45.67.89` in this example):

```
sudo route -n add 123.45.67.89/32 172.20.10.1
```

This will make sure your tunnel traffic will not be hijacked once the VPN is connected.

## Obfuscation

Since the modular rewrite of the application, multiple obfuscation methods can be selected. Obfuscation can be turned on by specifying the `-o` flag, this will result in the selection of the "simple generic header obfuscation" module with its built-in key.

Specifying a value for the `-o` flag allows selecting a different module, and the `-k` flag can be used to overwrite the built-in key for the selected module, which is highly recommended, but made optional for ease of use. (Note that the module is called "obfuscator" and not "military-grade encryptor", since its purpose is to try and mask the underlying traffic from automatic fingerprinting, not to encrypt sensitive data.)

### Simple generic header obfuscation

This is the default module, but also selectable with `-o header` explicitly. As it was specifically designed to disguise Wireguard headers, the algorithm used proceeds as follows:

* XORs the first 16 bytes of the UDP packet with a built-in key _or_ a one-byte key provided through `-k`.
* As the first 16 bytes of a Wireguard header contain 3 reserved always-zero bytes, and two more 32-bit counters (sender, receiver index) whose most significant bytes are mostly zero (especially at the beginning of the connection), in order to avoid fingerprinting by looking at the known gaps being XOR'd to the same value from the key, if the packet is long enough (>32 bytes), the next 16 bytes will be XOR'd into the first 16 bytes. In Wireguard, the next 16 bytes are already encrypted data, which means the packet's header will be not have static bytes where zero would be otherwise.

As Wireguard already does a great job of encrypting the traffic, the whole packet is not XOR'd, only the header, and only for masking purposes.

### XOR obfuscation

This module is selectable with `-o xor` and simply XORs the whole data stream with the built-in key or the one specified with `-k`. The size of the key can be any number of bytes up to 1,500. If the packet is larger than the key, the key will be repeated.

If you would like to identify the packets as something else in the firewall, you should play around with setting known values that look like a different protocol in the fields of the UDP packet, where Wireguard has reserved bytes, or bytes that you can map back from WG to the protocol you're trying to imitate, for example the packet type byte.

## Protocol imitation

While the application was originally developed to work in the network (e.g. ICMP) and transport (e.g. TCP, UDP) layers, support has been for imitating application (e.g. DNS, HTTP) layer protocols that run under their supported transport layers.

Protocol imitators (called "mockers" in the application) work on top of the transport layers, and may initiate a handshake that looks like the protocol they are trying to imitate, and then encapsulate the datastream in a way that it would look like it is legit traffic from the protocol they are trying to imitate.

When used together with an obfuscator, the obfuscator will process the data before the encapsulation by the mocker, otherwise, the protocol being imitated would be obfuscated as well.

### DNS imitator

The DNS imitator can be turned on using the `-m dns_client` flag on the local server, and with `-m dns_server` on the gateway server. It can work on top of the UDP and TCP transports, as DNS supports both. (Note that it can be run with ICMP endpoints as well, but a warning will be produced by the application, as it does not make much sense to encapsulate ICMP Echo Requests into DNS queries.)

The module will send DNS `A` queries to the remote server, which will reply with DNS `A` responses, where the "hostname" field will contain your data. The module does not try to emulate a complete DNS server, only produce DNS-like traffic, as such it will not be able to properly respond to DNS requests that are not from this application.

The DNS packets will look completely valid as long as the data sent is up to 255 bytes in length and plain-text. While the module will send binary bytes beyond 255 in length, these packets may be identified as corrupted by the firewall or other packet sniffers.

Example usage:

```
client$ ./tunnel -l udp:127.0.0.1:8080 -r udp:server:53 -m dns_client
server$ ./tunnel -l udp:0.0.0.0:53 -r udp:engage.cloudflareclient.com:2408 -m dns_server
```

Sending a packet with the bytes `test message` to the local endpoint will be delivered to the gateway server as such:

```
Source -    Destination -   Protocol -   Length -   Info -
localhost   test_server     DNS          62         Standard query 0x1337 A test message

[+] User Datagram Protocol, Src Port: 63542 (63542), Dst Port: domain (53)
[-] Domain Name System (query)
      Transaction ID: 0x1337
  [-] Flags: 0x0100 Standard query
        0... .... .... .... = Response: Message is a query
        .000 0... .... .... = Opcode: Standard query (0)
        .... ..0. .... .... = Truncated: Message is not truncated
        .... ...1 .... .... = Recursion desired: Do query recursively
        .... .... .0.. .... = Z: reserved (0)
        .... .... ...0 .... = Non-authenticated data: Unacceptable
      Questions: 1
      Answer RRs: 0
      Authority RRs: 0
      Additional RRs: 0 
  [-] Queries
    [-] test message: type A, class IN
          Name: test message
          Name Length: 12
          Label Count: 1
          Type: A (Host Address) (1)
          Class: IN (0x0001)
```

The gateway server will then extract the data from the DNS packet before forwarding it to the remote server.

### Tunneling over public DNS servers

While the original purpose of the DNS imitator was to modify UDP packets to look like DNS requests, but not actually produce completely valid DNS requests that can be sent to public DNS servers, very experimental support has been added through the use of the `-f` and `-d` flags, that should be treated more as a proof-of-concept, rather than an "official feature" of the application.

The original implementation (that is still used when `-f -d` is not specified) shoved binary data as-is into the label field of the DNS request. This worked for IDS systems to identify the packet as DNS, and for Wireshark to parse it, however, once sent to a real DNS server, it was replied to with `SERVFAIL` due to the incorrect formatting of the labels. Turning on the `-f` flag, the application will make the following changes to the DNS packet crafting step:

- Base-32 encode the data and break it up to 60-byte pieces, as a DNS label can have a maximum of approximately 65 bytes per label. (In other words, that is the maximum length of a single subdomain name.)
- Change the request and response types from `A` to `TXT`, as it can fit data more easily during response, now that it has to "play by the rules".
- Keep track of the request domain, since public DNS servers will not forward responses to requests with differing DNS names, even if the transaction ID matches.
- Place the base-32 encoded response data into the `TXT` field of the packet, as an answer referencing the original request domain name.

The `-d` flag can be used to append a domain name to the request label. Once a packet crafted with the `-f` flag turned on is sent to a public DNS, it will send it to the registered nameserver of the domain specified with the `-d` flag.

#### Setup

In order to receive DNS request packets on your server for your domain, you first have to designate a zone (a subdomain) to have the authoritative nameserver set to the IP of your server.

In other words, you need to create a `NS` record for a subdomain you do not currently use, that points to another subdomain within your domain which has an `A` or `AAAA` record pointing to the server you want to receive the UDP packets for that subdomain on.

For example, if you want to receive packets for the lookups on public DNSes for the `*.t.example.com` zone, you need to create the following records:

```
t    IN  NS  ns.example.com.
ns   IN  A   123.45.67.89
```

This will make sure that once something tries to resolve anything `*.t.example.com`, the public DNS server will forward the packet to the nameserver responsible for it, `ns.example.com`, which has the address of your server, `123.45.67.89`.

You can quickly test this by running a netcat listener on your server on UDP port 53, and then try to resolve a domain from a separate computer, that would belong to that subdomain:

```
client$ nslookup test.t.example.com 1.1.1.1         | server$ nc -lu4vvp 53
Server:         1.1.1.1                             | Ncat: Version 7.70 ( https://nmap.org/ncat )
Address:        1.1.1.1#53                          | Ncat: Listening on 0.0.0.0:53
                                                    | Ncat: Connection from 162.158.17.35.
** server can't find test.t.example.com: SERVFAIL   | ��testtexamplecom)��
```

If you see your domain name in the netcat output, the test was successful. (The `SERVFAIL` for nslookup happened because your netcat listener didn't reply with a valid DNS packet before timeout.)

You should strive to use the shortest domain you own and set a 1-character subdomain on it, so you leave more space for data in your DNS packets, as discussed in later sections regarding the transmittable payload size issue.

#### Example usage

If you would like to tunnel UDP packets from port 8080 to the same port on the remote server at dns.example.com, over the Google Public DNS for example, you can run the following commands:

```
server$ ./tunnel -l udp:0.0.0.0:53 -r udp:127.0.0.1:8080 -m dns_server -f -d t.example.com
client$ ./tunnel -l udp:127.0.0.1:8080 -r udp:8.8.8.8:53 -m dns_client -f -d t.example.com
```

Any packets sent to the local 8080 UDP port will be base-32 encoded, and a "DNS lookup" will be made with the DNS server located at 8.8.8.8, for the domain `<base32data>.dns.example.com`. The DNS server will then forward the DNS request packet to your server (as long as you have correctly set the NS record on dns.example.com to point to your own server), where a `TXT` reply packet will be sent back to the public DNS server, and forwarded back to you based on the transaction ID.

#### Caveats

**Caveat 1**: Increased latency

Public DNS servers are rate-limited and throttled, so you will not able to spam them with 1 Gbit of DNS packets and expect similar-rate reply. By only sending a few packets per second, and the MTU of those being very limited, any VPN connection tunneled over DNS will not work as expected. However, it _can_ be used for sending small packets back and forth without any issues, other than the ones being discussed in this section.

According to the Google Public DNS documentation, you will be blocked after attempting 1000 queries per second from the same IP. Cloudflare does not publish such a figure, but there are reports of IP blocks when huge volume of traffic is generated.

**Caveat 2**: Increased packet loss

One of the biggest issues in DNS tunneling, is that you can only reply to valid packets sent to you by the DNS server only once. This means that for each packet generated on your local server, turned into a DNS request, the remote server can only send one reply.

Furthermore, DNS servers will automatically reply with `SERVFAIL` after waiting for a certain period of time for a reply from your server, and it does not come.

All in all, it will work great for UDP protocols where there is an immediate response for each request, and no more data is sent afterwards by the server, however, it will not work if the server behind the tunnel takes too long to reply or wants to send data after the fact.

**Caveat 3**: Decreased MTU

Due to the limitations on the DNS label fields that you can put in the request packet, your upstream MTU will be severely limited as well. A DNS label (essentially a component "between the dots", or a subdomain name, for example) is limited to approximately 65 bytes per label. It is also limited to case-insensitive plain-text content only, so binary data needs to be base-32 encoded, which further reduces the amount of binary data you can transmit.

For responses, the DNS packet needs needs to include the original request in the reply, which leaves less room for response data if your request was too long.

This all makes the maximum transmission unit of such a DNS tunneling very low. Take these numbers as a reference, as there can be a few other influenting factors, such as the length of your domain name, and lower UDP MTU on your connection:

| Mode                  | Upstream | Downstream |
|-----------------------|----------|------------|
| Direct                | 1482     | 1482       |
| Direct with `-f`      | 914      | 915        |
| Direct with `-f/d`    | 880      | 898        |
| Google DNS            | 147      | 283        |
| Cloudflare DNS        | 147      | 283        |
| Quad9 <sup>1</sup>    | 2 ~ 136  | 281        |
| OpenDNS               | 36       | 283        |
| Residential ISP       | 147      | 158        |

1. Quad9 forwarded the queries to the server correctly, but most of the times replied with `SERVFAIL` instead of forwarding the bigger packets back. The downstream, that is decoded bytes in the `TXT` section of the reply, was constantly 281, but larger upstream packets, that is decoded bytes stored as part of the domain lookup, were randomly dropped. It might be possible that Quad9 has a system for recognizing malicious looking domains, and most of the times the confidence score on the tunnel domains were above the threshold.

#### Comparison with iodine/dnscat

The applications which were specifically written for DNS tunneling have code for probing what types of DNS packets you can send through the chain, in order to maximize MTU. Furthermore, they also have a "traffic manager" component, where large data is split up and sent in batch, then small requests are continously made for polling purposes, to see if there is any data to be received.

This application has support for generating valid DNS packets more as a proof-of-concept, and you should be not using it over iodine/dnscat, unless your use-case fits into the very specific use-case where this tunnel can work without issues but you have difficulty using it with the other purpose-built applications.

### HTTP WebSocket imitator

The HTTP WebSocket imitator can be turned on using the `-m http_ws_client` flag on the local server, and with `-m http_ws_server` on the gateway server. It can work only on top of TCP transports.

When the `http_ws_server` module is run, the local TCP endpoint will first require a valid handshake before the data is forwarded. If the client sends a valid HTTP request to upgrade to a websocket connection, the endpoint will reply with `101 Switching Protocols`, and any further packets will be forwarded to the remote endpoint on the gateway server. If the client fails to send a request which the application can interpret, it will reply with `404 Not Found` and close the connection.

Just like in the case of the DNS imitator, there is no real HTTP server implementation behind the scenes, but for the sake of completion, it will behave as real server and send HTTP error codes if a client other than this application tries to connect to it.

By default, the HTTP request being mimicked will try to connect to `docs.microsoft.com` and upgrade the `/updates` endpoint to a websocket connection. If you would like to hide the tunnel behind a real webserver, you may configure a real webserver to proxy to the application.

Example configuration for nginx to match the defaults:

```
server {
    listen       80;
    server_name  docs.microsoft.com;

    location /updates {
        proxy_pass      http://127.0.0.1:8080;
    }
}
```

You can run this `server` instance alongside your other websites without any interference with them. To run a compatible tunnel on the same server where nginx is running, run:

```
server$ ./tunnel -l tcp:127.0.0.1:8080 -r udp:engage.cloudflareclient.com:2408 -m http_ws_server
```

You can also replace the `tcp` protocol to `tls` (and the port number accordingly) in the `-r` argument, if you would like to connect to your gateway server via HTTPS.

## UDP tunneling

The UDP tunneling part of the application is pretty straightforward, packets are sent to the destination as they are received, and vice-versa, unless obfuscation is enabled, in which case the algorithm will first process the packet, but the length of the payload is never modified.

The most important information to be highlighted in this section, is that since this application was meant for personal use, it does not support any sort of NAT-ing. More specifically, it does not keep track of each client in order to route the packet responses back individually. It was designed to do the opposite: allow easy roaming over networks, therefore, response packets will be sent back to the last known address which sent a valid packet.

In its current state, it may be possible to temporarily hijack the data stream if the endpoint of the gateway is known, by sending a valid packet to the gateway. In case of obfuscation being turned on, the packet can be "validated" by making sure the algorithm has correctly decrypted the traffic, however, without obfuscation and appending any sort of header to the packet, the data stream is open for hijacks. This should not be a major issue, as once your local client sends another packet, the data stream will be restored back to you, given that your application can gracefully deal with the packets lost _and_ the data stream is properly encrypted, so you did not leak anything of use to the random port scanning passerby.

### DTLS encryption

If you would like to wrap the UDP-to-UDP tunnel into the datagram-specific version of TLS, you can replace the `udp` protocol in `-l` or `-r` to `dtls`.

As it uses the standard OpenSSL implementation of DTLS, you can connect directly to a DTLS application as the remote, without needing a second tunnel as the gateway to unwrap the DTLS:

```
$ ./tunnel -l dtls:127.0.0.1:8080 -r udp:127.0.0.1:8081
Started UDP server at 127.0.0.1:8080
Generating temporary self-signed certificate for 127.0.0.1...
Fingerprint of certificate is 6ef4:91bb:14b8:36a1:23c4:ca26:1376:ffae:1b9f:d15c
Waiting for first client...
Client connected via UDP from 127.0.0.1:61948
Established DTLSv1.2 using ECDHE-RSA-AES256-GCM-SHA384.
Started UDP client for 127.0.0.1:8081

$ openssl s_client -dtls -connect 127.0.0.1:8080
CONNECTED(00000003)
---
Certificate chain
 0 s:CN = 127.0.0.1
   i:CN = 127.0.0.1
---
[...]
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : DTLSv1.2
[...]
---
test
DONE

$ nc -luvp 8081
Received packet from 127.0.0.1:63844 -> 127.0.0.1:8081 (local)
test
^D
```

Futher arguments are available to control certificate management, see the **TLS encryption** section under **TCP tunneling** to learn about them, as the same applies to DTLS.

## TCP tunneling

The application has support for tunneling UDP packets over TCP. In order to do this, you will have to run the TCP listener on your gateway server first, and then connect from your local client:

```
server$ ./tunnel -l tcp:0.0.0.0:80 -r udp:engage.cloudflareclient.com:2408
client$ ./tunnel -r tcp:server:80 -l udp:127.0.0.1:2408

# edit wg0.conf to connect to 127.0.0.1:2408 instead of engage.cloudflareclient.com:2408
client$ wg-quick up wg0
```

By default, or when set explicitly with the `-e v` flag, TCP packets start with a length-value, a 16-bit unsigned field that is of variable length, due to an encoding scheme which uses the most significant bit in the byte to determine if more bytes are needed to be read in order to decode the full length of the payload. Using this method, there will be no fingerprintable zero bytes which are always present in the packet.

In its current form, the variable encoding will place 1 byte in the payload for lengths up to 127 bytes, 2 bytes to represent lengths up to 16,383, and caps out at 3-bytes for values of up to 32,767. As the MTU for an UDP packet over the internet generally does not exceed 1,500 bytes, capping out at 32k should not be a problem by far. (However, the cap can be easily extended by modifying the source code, as the underlying encoding scheme supports any sizes.)

If the variable-length encoding does not fit your purpose, for example, you're trying to connect to a service directly or imitate a protocol, you can set a more standard 16-bit unsigned short header in network byte order, using the `-e s` flag.

### Headerless forwarding

It is possible to turn off the length header prepended to TCP packets using the `-e n` flag. This allows for native forwarding from UDP to TCP or TCP to UDP without needing a second intermediary tunnel from the application to strip off the length header.

For UDP-based protocols, using UDP to TCP to UDP, however, turning off the length header will result in the UDP packets not being correctly reassembled on the gateway due to fragmentation occuring at the TCP stage, that the gateway server will not be aware of.

In this case, it depends on the application consuming the UDP packets whether it can consume fragmented and/or merged UDP packets. For Wireguard, the connection will mostly be stable, but some performance degradation will occur, as when the header does not align to be the very first byte in the UDP packet, Wireguard will drop it.

### TLS encryption

If you would like to expose a TCP server through standard TLS, or connect to a TLS server (similar to stunnel), you can replace the `tcp` protocol in either `-l` or `-r` to `tls`.

TLS has two operating modes for clients:

- By default, `--tls-no-verify` is not specified and `--tls-ca-bundle` is loaded from standard path. In this case, the TLS certificate of the remote host is validated, and the connection is dropped if the validation failed.
- If `--tls-no-verify` is specified, the certificate of the remote server will not be verified, however the fingerprint of the certificate will printed for manual verification purposes.

For servers, it is similar:

- By default, a self-signed certificate will be generated having the `CN` value set to the hostname specified in the `-l` argument, and the fingerprint will be printed.
- If `--tls-cert` and `--tls-key` are provided, the server will identify itself with that certificate.

For example, if you would like to connect two UDP tunnels via self-signed TCP/TLS:

```
$ ./tunnel -l tls:127.0.0.1:8081 -r udp:127.0.0.1:8082
Started TCP server at 127.0.0.1:8081
Generating temporary self-signed certificate for 127.0.0.1...
Fingerprint of certificate is da41:c3d2:7211:dec5:4a8e:3cda:ec12:7852:6eda:e0aa
Waiting for first client...
Client connected via TCP from 127.0.0.1:60987
Established TLSv1.3 using TLS_AES_256_GCM_SHA384.
Started UDP client for 127.0.0.1:8082

$ ./tunnel -l udp:127.0.0.1:8080 -r tls:127.0.0.1:8081 --tls-no-verify
Started UDP server at 127.0.0.1:8080
Connecting via TCP to 127.0.0.1:8081... Connected.
Established TLSv1.3 with 127.0.0.1 using TLS_AES_256_GCM_SHA384.
Fingerprint of certificate is da41:c3d2:7211:dec5:4a8e:3cda:ec12:7852:6eda:e0aa
Client connected via UDP from 127.0.0.1:62463

$ nc -vu 127.0.0.1 8080
test

$ nc -luvp 8082
Received packet from 127.0.0.1:62605 -> 127.0.0.1:8082 (local)
test
```

As another example, if you would like to expose a TLS server to a local non-TLS port: (Similar to stunnel.)

```
$ ./tunnel -l tls:0.0.0.0:443 -r tcp:127.0.0.1:80 -e n --tls-cert cert.pem --tls-key cert.key
Started TCP server at 0.0.0.0:443
Loaded certificate for example.com, issued by Let's Encrypt Authority X3.
Waiting for first client...
Client connected via TCP from 127.0.0.1:60819
Established TLSv1.3 using TLS_AES_256_GCM_SHA384.
Connecting via TCP to 127.0.0.1:80... Connected.

$ ncat --ssl 127.0.0.1 443
test

$ nc -lvp 80                           
Connection from 127.0.0.1:60820
test
```

### SOCKSv5 proxy

The application can connect to the remote gateway through a SOCKSv5 proxy, when the SOCKSv5 protocol imitator is enabled. In order to do this, you will have to specify `-m socks5:ip:port`, where `ip` and `port` should be substituted in with their corresponding values.

Although in theory SOCKSv5 supports UDP forwarding, in practice the majority of servers do not implement this feature, so it is not currently supported in the tunnel either. This means that the remote has to be a TCP endpoint (`-r tcp:` or `-r tls:`) in order for the module to work.

In its current form, the SOCKSv5 functionality is implemented as a protocol mocker, as that was the fastest way to implement such a feature via the provided API:

1. During `mocker->setup()`, the remote address is swapped to connect to the SOCKSv5 proxy instead;
2. During `mocker->handshake()`, it instructs the SOCKSv5 proxy to connect to the TCP remote address;
3. If the SOCKSv5 proxy sends a success message, the socket is handed over to the application, as any subsequent messages will be relayed to the gateway through the proxy.

Example usage to SSH through Tor: (Note, as we are connecting directly to SSH, and not to a gateway tunnel, `-e n` is specified to omit the payload length header.)

```
$ ./tunnel -l tcp:127.0.0.1:2222 -r tcp:12.34.56.78:22 -m socks5:127.0.0.1:9050 -e n  |
Started TCP server at 127.0.0.1:2222                                                  |
Waiting for first client...                                                           | $ ssh -p2222 127.0.0.1
Client connected via TCP from 127.0.0.1:53811                                         | Linux [...]
Connecting via TCP to 127.0.0.1:9050... Connected.                                    | Last login: [...]
Connecting via SOCKSv5 proxy to 12.34.56.78:22... Connected.                          | host $ 
```

## ICMP tunneling

The application supports bi-directional forwarding of UDP packets disguised as an ICMP ping/reply stream. Although this method can work perfectly and produce a high throughput (see Benchmark section), there are a few caveats you should be aware of, and take into consideration before reaching for the ICMP tunnels.

### Special privileges

First of all, you need to have root privileges on both the server and client in order to use ICMP tunnels, since they use raw sockets. On Unix and Unix-like operating systems, if you wish to allow users without root privileges to run the application, you can do so by running:

```
chmod +s tunnel
chown root:root tunnel
```

This will activate the  `SUID`  bit, which will allow the application to escalate to root when run by an unprivileged user. If you do not wish to run the application as root, on Linux, you have the option of using the capabilities system:

```
setcap cap_net_raw+eip tunnel
```

This will specifically allow the use of raw sockets for the application when run by unprivileged users, and does not execute the application with root privileges, as the `SUID` bit would.

### System preparation

As the application sends ICMP Echo Requests, the operating system will be happy to jump in and respond back to those requests with an ICMP Echo Reply before it gets to the application. While this would still work as the packet would eventually still reach the application, the throughput will be cut in half due to sending two packets for each request, one of which will need to be discarded by the client, otherwise you will run into application errors.

On Linux, you can turn off answering ICMP Echo Requests (only needed on the gateway server) by issuing the following command as root:

```
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all
```

In case of ICMPv6, a different command needs to be issued, as it is treated as a different protocol that does not inherit ICMP's settings: (Note that the first `_` changes to `/`, that is not a typo.)

```
echo 1 > /proc/sys/net/ipv6/icmp/echo_ignore_all
```

### Possible NAT issues

By default, in order to make sure non-tunnel ICMP Echo Requests cannot hijack the data stream, there is a hardcoded identifier number and a sequential sequence number that is kept in sync between requests and replies.

Unfortunately, some NATs are replacing the identifier and sequence numbers to completely random values in the ICMP Echo Request reaching the gateway server, but will be translated back to their original values once the gateway server sends the ICMP Echo Reply. This means that the client can filter by the magic number in the identifier, and keep track of the sequence, but the gateway server cannot.

As a result, if you are behind such a NAT, you must turn on the "expect identifier and sequence randomization" (`-x` flag) feature on the gateway server (the one running with `-l icmp:`). This will ensure that the gateway server will not filter by magic identifier, and does not increment the sequence number -- as the NAT would not route a different sequence back to the same client.

The downside of this is that the gateway server will receive all ICMP Echo Requests coming to the server, and may reply to them if the remote UDP server produces a result. (In case of Wireguard, packets that are not correctly formatted and encrypted will not receive any sort of reply, so this is mostly a non-issue.)

### Libpcap

PCAP support can be turned on using the `-p` flag when ICMP or ICMPv6 tunnels are used. When PCAP support is turned on, ICMP packets are not read from the raw socket, but instead sniffed from the network interface. This allows a significantly better throughput (see Benchmark section) and should always be used when the application can be compiled with libpcap support.

Reading the ICMP packets from the raw socket seems to not be stable, as the kernel seems to be very selective about which Echo Reply packets are forwarded to the application. Those with previously unseen sequence number or duplicate identifier are filtered out, and this drops the throughput by a large margin.

### Mode of operation

As the only suitable ICMP packet type which can freely send data back and forth is Echo Request/Reply (also known as "ping"), UDP packets are disguised within valid "ping" packets whose data is set to payload of the UDP packet.

Given that it is assumed the client is behind a restrictive firewall without a public IP, and the gateway server has a public IP, a hole-punching methodology needs to be used in order to open a bi-directional ICMP data stream. The ICMP packets sent by the client are always Echo Request packets, to which the gateway server replies with Echo Reply packets. This is needed, as the gateway server would otherwise not be able to "ping" you back, only if you already send a "ping request", at which point the NAT/firewall will know where to route back the "ping response" to within the network.

In more technical terms, if the router receives an Echo Request packet, it will reply to it without forwarding it to the device on which the application is running. If the router receives an Echo Reply packet with an identifier and sequence number which it has not previously seen (as in, not yet sent by the application to the gateway first), it will just discard it.

It is also important to note that unless the client has some sort of keepalive mechanism, the route will eventually be purged from the NAT's routing table, and any packets from the server will be lost. As the same issue can appear with UDP, most VPN protocols already have a keepalive mechanism, and this will translate back into the ICMP tunnel, so there should be no problems.

As ICMP traffic does not have port numbers, any random ICMP ping traffic might be able to hijack your data stream. In order to protect against this, the tunnels use a hardcoded identifier number, and discard any ICMP traffic that does not have this. The sequence number is also correctly tracked, in order to make sure the NAT rules are updated properly within the router, and not purged due to inactivity for the same number.

## ICMPv6 tunneling

At the IP layer, ICMPv6 is considered to be a different protocol from ICMP, and also has different fields and packet type numbers that would otherwise serve the same purpose. In order to not over-complicate the ICMP tunnel code, the two versions are currently not sharing the same codebase.

The most important distinction between the two tunnels, is that there seems to be an issue with larger packets within the ICMPv6 tunnels, and I haven't yet been able to track down what exactly is causing this. This issue can introduce a performance hit, as some packets are dropped, and that in turn will cause the TCP windowing algorithm to restart from the bottom within the tunneled VPN traffic.

In order to work around this, you can simply set the MTU a bit lower within your VPN solution. For Wireguard, an MTU of 1300 seems to do the trick perfectly. In order to set this, you can edit the configuration file on your _client_ (which connects to the ICMP tunnel) and add the following line:

```
[Interface]
MTU = 1300
```

There is no need to edit anything on the server-side, so it will work perfectly even if you do not have access to the destination Wireguard server, as it is for example a commercial VPN provider.

## MTU detection

Two scripts are provided within the repository which can be used to measure the maximum transmission unit over your connection within your tunneling setup (transports used, encapsulation, obfuscation, etc).

The `mtu-server.py` script creates a simple UDP server, and replies with the length and checksum of every packet received:

```
$ ./mtu-server.py
usage: ./mtu-server.py port
```

The `mtu-tester.py` script tries to determine which is the largest packet that the MTU server can safely receive and reply to. It uses binary search to efficiently pin-point the MTU for packet sizes between 1 and 10,000 bytes by default:

```
$ ./mtu-tester.py
usage: ./mtu-tester.py host port
```

Example usage to measure the MTU of a DNS-encapsulation tunnel:

```
client$ ./tunnel -l udp:127.0.0.1:8080 -r udp:server:53 -m dns_client -o xor -v
Obfuscating packets with XOR and built-in key.
Encapsulating packets into DNS queries.
Started UDP server at 127.0.0.1:8080
Started UDP client for server:53
[...]

server$ ./tunnel -l udp:0.0.0.0:53 -r udp:127.0.0.1:8080 -m dns_server -o xor -v
Obfuscating packets with XOR and built-in key.
Encapsulating packets into DNS replies.
Started UDP server at 0.0.0.0:53
Started UDP client for 127.0.0.1:8080
[...]

client$ ./mtu-tester.py 127.0.0.1 8080                 │ server$ ./mtu-server.py 8080
Testing with endpoint at ('127.0.0.1', 8080)           │ Listening at ('0.0.0.0', 8080)
Trying 5000 bytes: incorrect size received from server │ Received 1482 bytes
Trying 2500 bytes: incorrect size received from server │ Received 1482 bytes
Trying 1250 bytes: correct data                        │ Received 1250 bytes
Trying 1875 bytes: incorrect size received from server │ Received 1482 bytes
Trying 1562 bytes: incorrect size received from server │ Received 1482 bytes
Trying 1406 bytes: correct data                        │ Received 1406 bytes
Trying 1484 bytes: incorrect size received from server │ Received 1482 bytes
Trying 1445 bytes: correct data                        │ Received 1445 bytes
Trying 1464 bytes: correct data                        │ Received 1464 bytes
Trying 1474 bytes: correct data                        │ Received 1474 bytes
Trying 1479 bytes: correct data                        │ Received 1479 bytes
Trying 1481 bytes: correct data                        │ Received 1481 bytes
Trying 1482 bytes: correct data                        │ Received 1482 bytes
Trying 1483 bytes: incorrect size received from server │ Received 1482 bytes
MTU: 1482                                              │
```

Knowing the tunnel can safely encapsulate at maximum 1,482 bytes, we can now set the MTU of the VPN interface to this value, and the connection should not be unstable anymore due to dropped or incomplete packets:

```
[Interface]
MTU = 1482
```

## Benchmark

The setup chosen for the benchmark is that a local PC is connected behind a firewalled router to a public server acting as a gateway. The gateway server then forwards all packets to CloudFlare Warp.

| Mode | Latency | Download | Upload |
|-------------------------------|---------|----------|----------|
| Direct to Warp | 14 ms <sup>(1)</sup> | 210 Mbps | 240 Mbps |
| UDP-UDP | 44 ms | 170 Mbps | 210 Mbps |
| UDP-TCP | 44 ms | 170 Mbps | 180 Mbps |
| UDP-ICMP (pcap) | 44 ms | 130 Mbps | 170 Mbps |
| UDP-ICMP <sup>(2)</sup> | 73 ms | 2.5 Mbps | 120 Mbps |

1.  There is a 19 ms latency between the PC and the gateway, this will added to the tunneled results. So when calculating the overhead purely for the application, latency calculations should start by taking 33 ms as the base latency.
2.  It seems that not all ICMP Echo Replies are delivered correctly, even if the identifier and sequence number are correct, which is causing the massive drop in throughput. To fix this, you can turn on the PCAP feature with the `-p` flag.

In order to test the tunneling overhead over a non-ideal "real world scenario", a similar test was conducted using a 4G connection:

| Mode | Latency | Download | Upload |
|-------------------------------|---------|----------|----------|
| Direct to Warp | 46 ms | 52 Mbps | 20 Mbps |
| UDP-UDP | 83 ms | 50 Mbps | 19 Mbps |
| UDP-TCP | 107 ms | 49 Mbps | 16 Mbps |
| UDP-ICMP <sup>(1)</sup> | 84 ms | 45 Mbps | 12 Mbps |

1.  Out of the 4 tested 4G networks, one _sometimes_ did it, but another one _always_ tampered with the identifier and sequence numbers in the ICMP Echo Request packets. To use the tunnel on these connections, you will need to turn on the `-x` flag on the gateway server. (See "Possible NAT issues".)

## IPv6 support

There is no full IPv6 support in the application at this time, only the ICMPv6 tunnels accept IPv6 addresses and/or resolve hostnames to IPv6 addresses. There is an experimental branch `ipv6` which introduces full IPv6 support via the introduction of dual-stacked sockets. Unfortunately, this branch was not yet merged back to master, as it has some issues with the way IP addresses are returned by `accept()` and `recvfrom()`. Attempts have been made to uniformly upgrade all `sockaddr_in` addresses to v6-mapped IPv4 addresses in `sockaddr_in6` structures, but unfortunately the application still ended up with a few random `Address family not supported` errors. As the code is being refactored to make sure the tunnels are as simple as they can be, another attempt will soon be made to switch dual-stacked sockets back on.

## Future work

* Finish full IPv6 support.
* ~~Rewrite application to have separate "local server" and "remote client" components, that way the modes of operation are not fused together in one component (e.g. `-m ui6` for UDP-to-ICMPv6) but instead selectable separately (e.g. `-l udp:... -r icmpv6:...`).~~ Done.
* ~~Add support for obfuscation methods which can resize the payload, that way encryption headers can be added and there is more flexibility if protocols need to be concealed to look like other protocols.~~ Done.