#include "shared.cpp"
#include "tcp_server.cpp"
#include "udp_client.cpp"

int tcp_udp_tunnel(struct session *s)
{
    auto local = new tcp_server(s);
    auto remote = new udp_client(s);

    loop_transports_thread(local, remote, s->obfuscate);
    
    return 0;
}
