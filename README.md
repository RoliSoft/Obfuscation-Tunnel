# Obfuscation Tunnel

The purpose of this project is two-fold:

* Implement a high-performance and low-overhead UDP-to-UDP tunnel, which has support for encrypting/obfuscating the encapsulated traffic in order to avoid fingerprinting. (Initially developed specifically for masking Wireguard headers.)
* Implement a tunnel which can change the transport protocol from UDP to TCP or ICMP(/v6) in order to evade firewalls which block non-fingerprintable/whitelisted UDP packets, or just UDP traffic outright.

## Usage

```
usage: ./tunnel -r addr:port [args]
arguments:

   -r addr:port Remote host to tunnel packets to.
   -l addr:port Local listening address and port.
                  Optional, defaults to 127.0.0.1:8080
   -m mode      Operation mode. Possible values:
                  uu - UDP-to-UDP (Default)
                  ut - UDP-to-TCP
                  tu - TCP-to-UDP
                  ui - UDP-to-ICMP (Requires root)
                  iu - ICMP-to-UDP (Requires root)
                  ui6 - UDP-to-ICMPv6 (Requires root)
                  i6u - ICMPv6-to-UDP (Requires root)
   -p           Use PCAP, only applicable to ICMP tunnels, highly recommended.
   -o           Enable generic header obfuscation.
   -v           Detailed logging at the expense of decreased throughput.
   -h           Displays this message.
```

Example for UDP-to-UDP tunnel:

```
server$ ./tunnel -l 0.0.0.0:80 -r engage.cloudflareclient.com:2408 -m uu
client$ ./tunnel -r server:80 -l 127.0.0.1:2408 -m uu
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
* Find the `CFLAGS` line (should be the first),
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

In the current version, obfuscation can be turned on with the `-o` flag. As it was specifically designed to disguise Wireguard headers, the algorithm used proceeds as follows:

* XORs the first 16 bytes of the UDP packet with a key.
* As the first 16 bytes of a Wireguard header contains 3 reserved always-zero bytes, and two more 32-bit counters (sender, receiver index) whose most significant bytes are mostly zero (especially at the beginning of the connection), in order to avoid fingerprinting by looking at the known gaps being XOR'd to the same value from the key, if the packet is long enough (>32 bytes), the next 16 bytes will be XOR'd into the first 16 bytes. In Wireguard, the next 16 bytes are already encrypted data, which means the packet's header will be not have static bytes where zero would be otherwise.

As Wireguard already does a great job of encrypting the traffic, the whole packet is not XOR'd, only the header, and only for masking purposes.

If you find that the algorithm being used in this application has been implemented in the firewall, and your packets are identified, you may tweak the algorithm to your liking in `shared.c` function `obfuscate_message()`.

If you would like to identify the packets as something else in the firewall, you should play around with setting known values that look like a different protocol in the fields of the UDP packet, where Wireguard has reserved bytes, or bytes that you can map back from WG to the protocol you're trying to imitate, for example the packet type byte.

## UDP tunneling

The UDP tunneling part of the application is pretty straightforward, packets are sent to the destination as they are received, and vice-versa, unless obfuscation is enabled, in which case the algorithm will first process the packet, but the length of the payload is never modified.

The most important information to be highlighted in this section, is that since this application was meant for personal use, it does not support any sort of NAT-ing. More specifically, it does not keep track of each client in order to route the packet responses back individually. It was designed to do the opposite: allow easy roaming over networks, therefore, response packets will be sent back to the last known address which sent a valid packet.

In its current state, it may be possible to temporarily hijack the data stream if the endpoint of the gateway is known, by sending a valid packet to the gateway. In case of obfuscation being turned on, the packet can be "validated" by making sure the algorithm has correctly decrypted the traffic, however, without obfuscation and appending any sort of header to the packet, the data stream is open for hijacks. This should not be a major issue, as once your local client sends another packet, the data stream will be restored back to you, given that your application can gracefully deal with the packets lost _and_ the data stream is properly encrypted, so you did not leak anything of use to the random port scanning passerby.

## TCP tunneling

The application has support for tunneling UDP packets over TCP. In order to do this, you will have to run the TCP listener on your gateway server first, and then connect from your local client:

```
server$ ./tunnel -l 0.0.0.0:80 -r engage.cloudflareclient.com:2408 -m tu
client$ ./tunnel -r server:80 -l 127.0.0.1:2408 -m ut

# edit wg0.conf to connect to 127.0.0.1:2408 instead of engage.cloudflareclient.com:2408
client$ wg-quick up wg0
```

TCP packets start with a length-value, a 16-bit unsigned field that is of variable length, due to an encoding scheme which uses the most significant bit in the byte to determine if more bytes are needed to be read in order to decode the full length of the payload. Using this method, there will be no fingerprintable zero bytes which are always present in the packet.

In its current form, the variable encoding will place 1 byte in the payload for lengths up to 127 bytes, 2 bytes to represent lengths up to 16,383, and caps out at 3-bytes for values of up to 32,767. As the MTU for an UDP packet over the internet generally does not exceed 1,500 bytes, capping out at 32k should not be a problem by far. (However, the cap can be easily extended by modifying the source code, as the underlying encoding scheme supports any sizes.)

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
2.  It seems that not all Echo Replies are delivered correctly, even if the Identifier and Sequence number are correct, which is causing the massive drop in throughput.

In order to test the tunneling overhead over a non-ideal "real world scenario", a similar test was conducted using a 4G connection:

| Mode | Latency | Download | Upload |
|-------------------------------|---------|----------|----------|
| Direct to Warp | 46 ms | 52 Mbps | 20 Mbps |
| UDP-UDP | 83 ms | 50 Mbps | 19 Mbps |
| UDP-TCP | 107 ms | 49 Mbps | 16 Mbps |
| UDP-ICMP <sup>(1)</sup> | 84 ms | 45 Mbps | 12 Mbps |

1.  Out of the 4 tested 4G networks, one always did it, and the second one _sometimes_ did it, more specifically they tampered with the ICMP packets, and the gateway server received the ICMP Echo Request with a randomized identifier and sequence number. When reaching back to the client, the identifier and sequence numbers were translated back to their original values, however, this means that the gateway server could not use the harcoded magic number for identification. This is an interesting scenario that was not taken into account up until testing, and further work is required to detect such tampering and work around it without user interaction.

## IPv6 support

There is no full IPv6 support in the application at this time, only the ICMPv6 tunnels accept IPv6 addresses and/or resolve hostnames to IPv6 addresses. There is an experimental branch `ipv6` which introduces full IPv6 support via the introduction of dual-stacked sockets. Unfortunately, this branch was not yet merged back to master, as it has some issues with the way IP addresses are returned by `accept()` and `recvfrom()`. Attempts have been made to uniformly upgrade all `sockaddr_in` addresses to v6-mapped IPv4 addresses in `sockaddr_in6` structures, but unfortunately the application still ended up with a few random `Address family not supported` errors. As the code is being refactored to make sure the tunnels are as simple as they can be, another attempt will soon be made to switch dual-stacked sockets back on.

## Future work

* Rewrite application to have separate "local server" and "remote client" components, that way the modes of operation are not fused together in one component (e.g. ui6 for UDP-to-ICMPv6) but instead selectable separately (e.g. `-l udp:... -r icmpv6:...`).
* Finish full IPv6 support.
* Add support for obfuscation methods which can resize the payload, that way encryption headers can be added and there is more flexibility if protocols need to be concealed to look like other protocols.