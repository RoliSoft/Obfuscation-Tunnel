CXXFLAGS = -std=c++14 -Wall -Wextra -Ofast -DHAVE_PCAP=1 -lpcap -lpthread

tunnel: main.cpp shared.cpp factory.cpp forwarders.cpp transport_base.cpp obfuscate_base.cpp simple_obfuscator.cpp xor_obfuscator.cpp udp_base.cpp udp_client.cpp udp_server.cpp tcp_base.cpp tcp_client.cpp tcp_server.cpp icmp_base.cpp icmp_client.cpp icmp_server.cpp icmp6_base.cpp icmp6_client.cpp icmp6_server.cpp
	$(CXX) $(CXXFLAGS) main.cpp -o $@

clean:
	rm tunnel
