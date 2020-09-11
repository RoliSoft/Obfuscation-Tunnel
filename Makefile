CXXFLAGS = -std=c++14 -Wall -Wextra -Ofast -DHAVE_PCAP=1 -lpcap -lpthread

tunnel: main.cpp shared.cpp udp_base.cpp udp_client.cpp udp_server.cpp tcp_base.cpp tcp_client.cpp tcp_server.cpp icmp_base.cpp icmp_client.cpp icmp_server.cpp icmp6_base.cpp icmp6_client.cpp icmp6_server.cpp udp_udp_tunnel.cpp udp_tcp_tunnel.c tcp_udp_tunnel.c udp_icmp_tunnel.c icmp_udp_tunnel.c udp_icmp6_tunnel.c icmp6_udp_tunnel.c
	$(CXX) $(CXXFLAGS) main.cpp -o $@

clean:
	rm tunnel
