CFLAGS = -O3 -lpcap

tunnel: main.c shared.c udp_udp_tunnel.c udp_tcp_tunnel.c tcp_udp_tunnel.c udp_icmp_tunnel.c icmp_udp_tunnel.c
	$(CC) $(CFLAGS) main.c -o $@

clean:
	rm tunnel
