#include "shared.cpp"
#include "tcp_client.cpp"

int udp_tcp_tunnel(struct session *s)
{
    auto local = new udp_server(s->local_addr);
    auto remote = new tcp_client(s->remote_addr);

    // session will soon be removed altogether, move these manually for now
    local->verbose = s->verbose;
    remote->verbose = s->verbose;

    loop_transports_thread(local, remote, s->obfuscate);
    
    return 0;
}
