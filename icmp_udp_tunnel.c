#include "shared.cpp"
#include "icmp_server.cpp"
#include "udp_client.cpp"

int icmp_udp_tunnel(struct session *s)
{
    auto local = new icmp_server(s);
    auto remote = new udp_client(s);

    loop_transports_thread(local, remote, s->obfuscate);
    
    return 0;
}
