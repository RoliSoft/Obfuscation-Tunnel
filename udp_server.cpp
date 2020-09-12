#pragma once
#include "shared.cpp"
#include "udp_base.cpp"

class udp_server : public udp_base
{
private:
    int fd;
    struct sockaddr_in local_addr, client_addr;

public:
    udp_server(struct sockaddr_in local_addr, struct session* session)
        : transport_base(session->verbose), local_addr(local_addr)
    {
    }

    udp_server(struct sockaddr_in local_addr, bool verbose = false)
        : transport_base(verbose), local_addr(local_addr)
    {
    }

    int start()
    {
        if ((this->fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        { 
            perror("Server socket creation failed");
            return EXIT_FAILURE;
        }

        if (bind(this->fd, (const struct sockaddr *)&this->local_addr, sizeof(this->local_addr)) < 0)
        {
            perror("Bind failed");
            return EXIT_FAILURE;
        }

        printf("Started UDP server at ");
        print_ip_port(&this->local_addr);
        printf("\n");

        sockets.push_back(this->fd);
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

        return _send(this->fd, (const struct sockaddr*)&this->client_addr, buffer, msglen);
    }

    int receive(char *buffer, int* offset)
    {
        int res = _receive(this->fd, (struct sockaddr*)&this->client_addr, buffer, offset);

        if (!this->connected && res > 0)
        {
            this->connected = 1;

            printf("Client connected via UDP from ");
            print_ip_port(&this->client_addr);
            printf("\n");
        }

        return res;
    }

    int get_selectable()
    {
        return this->fd;
    }
};
