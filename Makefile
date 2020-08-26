CFLAGS = -Wall -Wextra -Wno-unknown-warning-option -Wno-cast-function-type -Ofast -DHAVE_PCAP=1 -lpcap -lpthread

tunnel: main.c shared.c udp_udp_tunnel.c udp_tcp_tunnel.c tcp_udp_tunnel.c udp_icmp_tunnel.c icmp_udp_tunnel.c udp_icmp6_tunnel.c icmp6_udp_tunnel.c
	$(CC) $(CFLAGS) main.c -o $@

clean:
	rm tunnel
