#pragma once
#include "shared.cpp"
#include "icmp6_base.cpp"

class icmp6_client : public icmp6_base
{
private:
    int fd;
    struct sockaddr_in6 remote_addr;

public:
    icmp6_client(struct session* session)
        : transport_base(session->verbose), icmp6_base(session->pcap, session->random_id), remote_addr(*(struct sockaddr_in6*)&session->remote_addr)
    {
    }

    icmp6_client(struct sockaddr_in6 remote_addr, bool pcap = false, bool random_id = false, bool verbose = false)
        : transport_base(verbose), icmp6_base(pcap, random_id), remote_addr(remote_addr)
    {
    }

    int start()
    {
        if ((this->fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0)
        { 
            perror("Client socket creation failed");
            return EXIT_FAILURE;
        }

        printf("Started ICMPv6 client for ");
        print_ip6(&this->remote_addr);
        printf("\n");

        sockets2.push_back(this->fd);
        started = true;

        return EXIT_SUCCESS;
    }

    int stop()
    {
        close(this->fd);

        started = false;

        return EXIT_SUCCESS;
    }

    int send(char *buffer, ssize_t msglen)
    {
        return _send(this->fd, false, (const struct sockaddr_in6*)&this->remote_addr, buffer, msglen);
    }

    int receive(char *buffer, int* offset)
    {
        return _receive(this->fd, false, (struct sockaddr_in6*)&this->remote_addr, buffer, offset);
    }

    int get_selectable()
    {
        return this->fd;
    }
};
