#include "shared.cpp"
#include "udp_server.cpp"
#include "icmp6_client.cpp"

int udp_icmp6_tunnel(struct session *s)
{
    auto local = new udp_server(s);
    auto remote = new icmp6_client(s);

    loop_transports_thread(local, remote, s->obfuscate);
    
    return 0;
}
