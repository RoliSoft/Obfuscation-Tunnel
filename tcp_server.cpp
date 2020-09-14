#pragma once
#include "shared.cpp"
#include "tcp_base.cpp"

class tcp_server : public tcp_base
{
private:
    int server_fd, client_fd;
    struct sockaddr_in local_addr, client_addr;

public:
    tcp_server(struct sockaddr_in local_addr, struct session* session)
        : transport_base(session->verbose), tcp_base(session->length_type), local_addr(local_addr)
    {
    }

    tcp_server(struct sockaddr_in local_addr, int encoding = LENGTH_VAR, bool verbose = false)
        : transport_base(verbose), tcp_base(encoding), local_addr(local_addr)
    {
    }

private:
    int _accept()
    {
        if (!run)
        {
            return EXIT_FAILURE;
        }

        socklen_t addrlen;
        this->client_fd = accept(this->server_fd, (struct sockaddr*)&this->client_addr, &addrlen);

        if (this->client_fd < 0)
        {
            if (run)
            {
                perror("Failed to accept incoming connection");
                return EXIT_FAILURE;
            }
            else
            {
                return EXIT_SUCCESS;
            }
        }

        sockets.push_back(this->client_fd);
        connected = true;

        printf("Client connected via TCP from ");
        print_ip_port(&this->client_addr);
        printf("\n");

        int i = 1;
        setsockopt(this->client_fd, IPPROTO_TCP, TCP_NODELAY, (void *)&i, sizeof(i));
#ifdef TCP_QUICKACK
        setsockopt(this->client_fd, IPPROTO_TCP, TCP_QUICKACK, (void *)&i, sizeof(i));
#endif

        return EXIT_SUCCESS;
    }

public:
    int start()
    {
        if ((this->server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        { 
            perror("Server socket creation failed");
            return EXIT_FAILURE;
        }

        if (bind(this->server_fd, (const struct sockaddr *)&this->local_addr, sizeof(this->local_addr)) < 0)
        {
            perror("Bind failed");
            return EXIT_FAILURE;
        }

        if (listen(this->server_fd, 1) != 0)
        {
            perror("Failed to listen on local port");
            return EXIT_FAILURE;
        }

        printf("Started TCP server at ");
        print_ip_port(&this->local_addr);
        printf("\n");

        sockets.push_back(this->server_fd);
        started = true;

        printf("Waiting for first client...\n");
        return _accept();
    }

    int restart()
    {
        printf("Waiting for next client...\n");
        return _accept();
    }

    int stop()
    {
        close(this->client_fd);
        close(this->server_fd);

        started = false;

        return EXIT_SUCCESS;
    }

    int send(char *buffer, ssize_t msglen)
    {
        if (!this->connected)
        {
            return 0;
        }

        int res = _send(this->client_fd, buffer, msglen);

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

        int res = _receive(this->client_fd, buffer, offset);

        if (res < 0)
        {
            this->connected = false;
        }

        return res;
    }

    int get_selectable()
    {
        return this->client_fd;
    }
};
