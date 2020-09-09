#include "shared.cpp"
#include "udp_server.cpp"
#include "tcp_client.cpp"

int udp_tcp_tunnel(struct session *s)
{
    auto local = new udp_server(s);
    auto remote = new tcp_client(s);

    loop_transports_thread(local, remote, s->obfuscate);
    
    return 0;
}
