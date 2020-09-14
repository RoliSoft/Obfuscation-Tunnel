#pragma once
#include "shared.cpp"
#include "tcp_base.cpp"

class tcp_client : public tcp_base
{
private:
    int fd;
    struct sockaddr_in remote_addr;

public:
    tcp_client(struct sockaddr_in remote_addr, struct session* session)
        : transport_base(session->verbose), tcp_base(session->length_type), remote_addr(remote_addr)
    {
    }

    tcp_client(struct sockaddr_in remote_addr, int encoding = LENGTH_VAR, bool verbose = false)
        : transport_base(verbose), tcp_base(encoding), remote_addr(remote_addr)
    {
    }

private:
    int _connect()
    {
        if (!run)
        {
            return EXIT_FAILURE;
        }

        int res;
        do
        {
            if ((this->fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
            { 
                perror("Client socket creation failed");
                return EXIT_FAILURE;
            }

            res = connect(this->fd, (const struct sockaddr *)&this->remote_addr, IP_SIZE);

            if (res == -1)
            {
                if (!run)
                {
                    return EXIT_FAILURE;
                }
                
                if (errno == ECONNREFUSED)
                {
                    close(this->fd);
                    sleep(1);
                    continue;
                }
                else
                {
                    perror("Failed to connect to remote host");
                    return EXIT_FAILURE;
                }
            }
        }
        while (res != 0);

        sockets.push_back(this->fd);
        started = true;
        connected = true;

        printf("Connected.\n");

        int i = 1;
        setsockopt(this->fd, IPPROTO_TCP, TCP_NODELAY, (void *)&i, sizeof(i));
#ifdef TCP_QUICKACK
        setsockopt(this->fd, IPPROTO_TCP, TCP_QUICKACK, (void *)&i, sizeof(i));
#endif

        return EXIT_SUCCESS;
    }

public:
    int start()
    {
        printf("Connecting via TCP to ");
        print_ip_port(&this->remote_addr);
        printf("... ");
        fflush(stdout);

        return _connect();
    }

    int restart()
    {
        close(this->fd);
        
        printf("Reconnecting via TCP to ");
        print_ip_port(&this->remote_addr);
        printf("... ");
        fflush(stdout);

        return _connect();
    }

    int stop()
    {
        close(this->fd);

        started = false;
        connected = false;

        return EXIT_SUCCESS;
    }

    int send(char *buffer, ssize_t msglen)
    {
        if (!this->connected)
        {
            return 0;
        }

        int res = _send(this->fd, buffer, msglen);

        if (res < 0)
        {
            this->connected = false;
        }

        return res;
    }

    int receive(char *buffer, int* offset)
    {
        if (!this->connected)
        {
            return 0;
        }

        int res = _receive(this->fd, buffer, offset);

        if (res < 0)
        {
            this->connected = false;
        }

        return res;
    }

    int get_selectable()
    {
        return this->fd;
    }
};
