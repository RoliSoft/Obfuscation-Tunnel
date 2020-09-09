#pragma once
#include "shared.cpp"
#include "udp_base.cpp"

class udp_client : public udp_base
{
private:
    int fd;
    struct sockaddr_in remote_addr;

public:
    udp_client(struct session* session)
        : transport_base(session->verbose), remote_addr(session->remote_addr)
    {
    }

    udp_client(struct sockaddr_in remote_addr, bool verbose = false)
        : transport_base(verbose), remote_addr(remote_addr)
    {
    }

    int start()
    {
        if ((this->fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        { 
            perror("Client socket creation failed");
            return EXIT_FAILURE;
        }

        printf("Started UDP client for ");
        print_ip_port(&this->remote_addr);
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
        return _send(this->fd, (const struct sockaddr*)&this->remote_addr, buffer, msglen);
    }

    int receive(char *buffer, int* offset)
    {
        return _receive(this->fd, (struct sockaddr*)&this->remote_addr, buffer, offset);
    }

    int get_selectable()
    {
        return this->fd;
    }
};
