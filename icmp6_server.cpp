#pragma once
#include "shared.cpp"
#include "icmp6_base.cpp"

class icmp6_server : public icmp6_base
{
private:
    int fd;
    struct sockaddr_in6 local_addr, client_addr;

public:
    icmp6_server(struct session* session)
        : transport_base(session->verbose), icmp6_base(session->pcap, session->random_id), local_addr(*(struct sockaddr_in6*)&session->local_addr)
    {
    }

    icmp6_server(struct sockaddr_in6 local_addr, bool pcap = false, bool random_id = false, bool verbose = false)
        : transport_base(verbose), icmp6_base(pcap, random_id), local_addr(local_addr)
    {
    }

    int start()
    {
        if ((this->fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0)
        { 
            perror("Server socket creation failed");
            return EXIT_FAILURE;
        }
        
        printf("Started ICMPv6 server at ");
        print_ip6(&this->local_addr);
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
        if (!this->connected)
        {
            return 0;
        }

        return _send(this->fd, true, (const struct sockaddr_in6*)&this->client_addr, buffer, msglen);
    }

    int receive(char *buffer, int* offset)
    {
        int res = _receive(this->fd, true, (struct sockaddr_in6*)&this->client_addr, buffer, offset);

        if (!this->connected && res > 0)
        {
            this->connected = 1;

            printf("Client connected via ICMPv6 from ");
            print_ip6(&this->client_addr);
            printf("\n");
        }

        return res;
    }

    int get_selectable()
    {
        return this->fd;
    }
};
