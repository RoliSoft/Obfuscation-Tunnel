#pragma once
#include "shared.cpp"
#include "icmp_base.cpp"

class icmp_client : public icmp_base
{
private:
    int fd;
    struct sockaddr_in remote_addr;

public:
    icmp_client(struct session* session)
        : transport_base(session->verbose), icmp_base(session->pcap, session->random_id), remote_addr(session->remote_addr)
    {
    }

    icmp_client(struct sockaddr_in remote_addr, bool pcap = false, bool random_id = false, bool verbose = false)
        : transport_base(verbose), icmp_base(pcap, random_id), remote_addr(remote_addr)
    {
    }

    int start()
    {
        if ((this->fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
        { 
            perror("Client socket creation failed");
            return EXIT_FAILURE;
        }

        printf("Started ICMP client for ");
        print_ip(&this->remote_addr);
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
        return _send(this->fd, false, (const struct sockaddr*)&this->remote_addr, buffer, msglen);
    }

    int receive(char *buffer, int* offset)
    {
        return _receive(this->fd, false, (struct sockaddr*)&this->remote_addr, buffer, offset);
    }

    int get_selectable()
    {
        return this->fd;
    }
};
