#include "shared.cpp"
#include "udp_server.cpp"
#include "icmp_client.cpp"

int udp_icmp_tunnel(struct session *s)
{
    auto local = new udp_server(s);
    auto remote = new icmp_client(s);

    loop_transports_thread(local, remote, s->obfuscate);
    
    return 0;
}
