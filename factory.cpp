#pragma once
#include "shared.cpp"
#include "udp_client.cpp"
#include "udp_server.cpp"
#include "tcp_client.cpp"
#include "tcp_server.cpp"
#include "icmp_client.cpp"
#include "icmp_server.cpp"
#include "icmp6_client.cpp"
#include "icmp6_server.cpp"

transport_base* create_transport(int protocol, struct sockaddr_in *address, bool server, struct session *session)
{
    switch (protocol)
    {
        case PROTO_UDP:
            if (server) return new udp_server(*address, session);
            else        return new udp_client(*address, session);
        
        case PROTO_TCP:
            if (server) return new tcp_server(*address, session);
            else        return new tcp_client(*address, session);

        case PROTO_ICMP:
            if (server) return new icmp_server(*address, session);
            else        return new icmp_client(*address, session);

        case PROTO_ICMP6:
            if (server) return new icmp6_server(*(struct sockaddr_in6*)address, session);
            else        return new icmp6_client(*(struct sockaddr_in6*)address, session);
        
        default:
            fprintf(stderr, "Protocol %d is not supported.\n", protocol);
            return nullptr;
    }
}

int run_session(struct session *session)
{
    transport_base *local = create_transport(session->local_proto, &session->local_addr, true, session);
    transport_base *remote = create_transport(session->remote_proto, &session->remote_addr, false, session);

    if (local == nullptr || remote == nullptr)
    {
        return EXIT_FAILURE;
    }

    int res;

    if (session->no_threading)
    {
        res = loop_transports_select(local, remote, session->obfuscate);
    }
    else
    {
        res = loop_transports_thread(local, remote, session->obfuscate);
    }

    //free(local);
    //free(remote);

    return res;
}
