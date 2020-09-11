CXXFLAGS = -std=c++14 -Wall -Wextra -Wno-unknown-warning-option -Wno-cast-function-type -Ofast -DHAVE_PCAP=1 -lpcap -lpthread -Wno-writable-strings

tunnel: main.cpp shared.cpp udp_base.cpp udp_client.cpp udp_server.cpp tcp_base.cpp tcp_client.cpp tcp_server.cpp icmp_base.cpp icmp_client.cpp udp_udp_tunnel.cpp udp_tcp_tunnel.c tcp_udp_tunnel.c udp_icmp_tunnel.c icmp_udp_tunnel.c udp_icmp6_tunnel.c icmp6_udp_tunnel.c
	$(CXX) $(CXXFLAGS) main.cpp -o $@

clean:
	rm tunnel
