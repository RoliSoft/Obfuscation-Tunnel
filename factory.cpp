#pragma once
#include "shared.cpp"
#include "forwarders.cpp"
#include "udp_client.cpp"
#include "udp_server.cpp"
#include "tcp_client.cpp"
#include "tcp_server.cpp"
#include "icmp_client.cpp"
#include "icmp_server.cpp"
#include "icmp6_client.cpp"
#include "icmp6_server.cpp"
#include "simple_obfuscator.cpp"
#include "xor_obfuscator.cpp"
#include "dns_mocker.cpp"
#include "http_ws_mocker.cpp"

transport_base* create_transport(int protocol, struct sockaddr_in *address, bool server, struct session *session)
{
    switch (protocol)
    {
        case PROTO_UDP:
            if (server) return new udp_server(*address, session);
            else        return new udp_client(*address, session);
        
        case PROTO_TCP:
            if (server) return new tcp_server(*address, false, session);
            else        return new tcp_client(*address, false, session);

        case PROTO_TLS:
            if (server) return new tcp_server(*address, true, session);
            else        return new tcp_client(*address, true, session);

        case PROTO_DTLS: // todo
            if (server) return new udp_server(*address, session);
            else        return new udp_client(*address, session);

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

obfuscate_base* create_obfuscator(struct session *session)
{
    if (session->obfuscator == nullptr)
    {
        return nullptr;
    }
    else if (strcmp(session->obfuscator, "header") == 0)
    {
        return new simple_obfuscator(session);
    }
    else if (strcmp(session->obfuscator, "xor") == 0)
    {
        return new xor_obfuscator(session);
    }
    else
    {
        fprintf(stderr, "'%s' is not a supported obfuscator.\n", session->obfuscator);
        return nullptr;
    }
}

mocker_base* create_mocker(struct session *session)
{
    if (session->mocker == nullptr)
    {
        return nullptr;
    }
    else if (strcmp(session->mocker, "dns_client") == 0 || strcmp(session->mocker, "dns_server") == 0)
    {
        return new dns_mocker(session);
    }
    else if (strcmp(session->mocker, "http_ws_client") == 0 || strcmp(session->mocker, "http_ws_server") == 0)
    {
        return new http_ws_mocker(session);
    }
    else
    {
        fprintf(stderr, "'%s' is not a supported mocker.\n", session->mocker);
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

    obfuscate_base *obfuscator = create_obfuscator(session);
    mocker_base *mocker = create_mocker(session);

    int res;

    if (session->no_threading)
    {
        res = loop_transports_select(local, remote, obfuscator, mocker);
    }
    else
    {
        res = loop_transports_thread(local, remote, obfuscator, mocker);
    }

    //free(local);
    //free(remote);

    return res;
}
