#include "shared.cpp"
#include "udp_server.cpp"
#include "udp_client.cpp"

int udp_udp_tunnel(struct session *s)
{
    auto local = new udp_server(s);
    auto remote = new udp_client(s);

    loop_transports_thread(local, remote, s->obfuscate);
    
    return 0;
}
