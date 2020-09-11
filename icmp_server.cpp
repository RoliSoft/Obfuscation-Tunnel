#pragma once
#include "shared.cpp"
#include "icmp_base.cpp"

class icmp_server : public icmp_base
{
private:
    int fd;
    struct sockaddr_in local_addr, client_addr;

public:
    icmp_server(struct session* session)
        : transport_base(session->verbose), icmp_base(session->pcap, session->random_id), local_addr(session->local_addr)
    {
    }

    icmp_server(struct sockaddr_in local_addr, bool pcap = false, bool random_id = false, bool verbose = false)
        : transport_base(verbose), icmp_base(pcap, random_id), local_addr(local_addr)
    {
    }

    int start()
    {
        if ((this->fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
        { 
            perror("Server socket creation failed");
            return EXIT_FAILURE;
        }
        
        printf("Started ICMP server at ");
        print_ip(&this->local_addr);
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

        return _send(this->fd, true, (const struct sockaddr*)&this->client_addr, buffer, msglen);
    }

    int receive(char *buffer, int* offset)
    {
        int res = _receive(this->fd, true, (struct sockaddr*)&this->client_addr, buffer, offset);

        if (!this->connected && res > 0)
        {
            this->connected = 1;

            printf("Client connected via ICMP from ");
            print_ip(&this->client_addr);
            printf("\n");
        }

        return res;
    }

    int get_selectable()
    {
        return this->fd;
    }
};
