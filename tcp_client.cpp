#pragma once
#include "shared.cpp"
#include "tcp_base.cpp"

class tcp_client : public tcp_base
{
private:
    int fd;
    struct sockaddr_in remote_addr;

public:
    tcp_client(struct session* session)
        : transport_base(session->verbose), tcp_base(session->omit_length), remote_addr(session->remote_addr)
    {
    }

    tcp_client(struct sockaddr_in remote_addr, bool omit_length = false, bool verbose = false)
        : transport_base(verbose), tcp_base(omit_length), remote_addr(remote_addr)
    {
    }

    int start()
    {
        if ((this->fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        { 
            perror("Client socket creation failed");
            return EXIT_FAILURE;
        }

        printf("Started TCP client for ");
        print_ip_port(&this->remote_addr);
        printf("\n");

        sockets2.push_back(this->fd);
        started = true;

        // todo extract elsewhere?
        printf("Connecting...\n");

        if (connect(this->fd, (const struct sockaddr *)&this->remote_addr, IP_SIZE) != 0)
        {
            perror("Failed to connect to remote host");
            return EXIT_FAILURE;
        }

        connected = true;

        int i = 1;
        setsockopt(this->fd, IPPROTO_TCP, TCP_NODELAY, (void *)&i, sizeof(i));
#ifdef TCP_QUICKACK
        setsockopt(this->fd, IPPROTO_TCP, TCP_QUICKACK, (void *)&i, sizeof(i));
#endif

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
        return _send(this->fd, buffer, msglen);
    }

    int receive(char *buffer, int* offset)
    {
        return _receive(this->fd, buffer, offset);
    }

    int get_selectable()
    {
        return this->fd;
    }
};
