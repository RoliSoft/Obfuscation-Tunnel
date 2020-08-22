CFLAGS = -O3

tunnel: main.c shared.c udp_udp_tunnel.c udp_tcp_tunnel.c tcp_udp_tunnel.c 
	$(CC) $(CFLAGS) main.c -o $@

clean:
	rm tunnel
