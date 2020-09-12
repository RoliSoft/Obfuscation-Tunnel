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

transport_base* create_server_transport(struct session *session)
{
    switch (session->local_proto)
    {
        case PROTO_UDP:
            return new udp_server(session);
        
        case PROTO_TCP:
            return new tcp_server(session);

        case PROTO_ICMP:
            return new icmp_server(session);

        case PROTO_ICMP6:
            return new icmp6_server(session);
        
        default:
            fprintf(stderr, "Local protocol %d is not supported.\n", session->local_proto);
            return nullptr;
    }
}

transport_base* create_client_transport(struct session *session)
{
    switch (session->remote_proto)
    {
        case PROTO_UDP:
            return new udp_client(session);
        
        case PROTO_TCP:
            return new tcp_client(session);

        case PROTO_ICMP:
            return new icmp_client(session);

        case PROTO_ICMP6:
            return new icmp6_client(session);
        
        default:
            fprintf(stderr, "Remote protocol %d is not supported.\n", session->remote_proto);
            return nullptr;
    }
}

int run_session(struct session *session)
{
    transport_base *local = create_server_transport(session);
    transport_base *remote = create_client_transport(session);

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
