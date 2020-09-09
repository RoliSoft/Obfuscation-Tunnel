#include "shared.cpp"

class tcp_server : public transport_base
{
private:
    int server_fd, client_fd;
    struct sockaddr_in local_addr, client_addr;

public:
    tcp_server(struct sockaddr_in local_addr)
        : local_addr(local_addr)
    {
    }

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

        sockets2.push_back(this->server_fd);
        started = true;

        // todo extract elsewhere?
        printf("Waiting for first client...\n");

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

        sockets2.push_back(this->client_fd);
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

        int sizelen = 0;
        write_14bit(msglen, buffer - sizeof(unsigned short), &sizelen);
        int sizediff = sizeof(unsigned short) - sizelen;

        if (sizediff == 1)
        {
            buffer[-1] = buffer[-2];
        }

        int res = write(this->client_fd, buffer - sizediff, msglen + sizelen);

        if (res < 0 && run)
        {
            perror("Failed to send TCP packet");
        }

        return res;
    }

    int receive(char *buffer, int* offset)
    {
        unsigned short toread = read_14bit(this->client_fd);

        if (toread == 0)
        {
            printf("TCP connection to client lost\n");
            return EXIT_FAILURE;
        }

        if (toread > MTU_SIZE)
        {
            printf("Incorrect size read from buffer, abandoning read.\n");
            return EXIT_FAILURE;
        }

        unsigned short readsize = toread;

        while (run && toread > 0)
        {
            ssize_t msglen = read(this->client_fd, buffer + (readsize - toread), toread);

            if (this->verbose && toread != msglen)
            {
                printf("Read partially, need %ld more bytes.\n", toread - msglen);
            }

            toread -= msglen;
        }

        if (this->verbose) printf("Received %zd bytes from client\n", readsize);

        *offset = 0;
        return readsize;
    }

    int get_selectable()
    {
        return this->client_fd;
    }
};
