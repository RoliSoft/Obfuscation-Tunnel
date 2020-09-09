#include "shared.cpp"

class tcp_client : public transport_base
{
private:
    int fd;
    struct sockaddr_in remote_addr;

public:
    tcp_client(struct sockaddr_in remote_addr)
        : remote_addr(remote_addr)
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
        int sizelen = 0;
        write_14bit(msglen, buffer - sizeof(unsigned short), &sizelen);
        int sizediff = sizeof(unsigned short) - sizelen;

        if (sizediff == 1)
        {
            buffer[-1] = buffer[-2];
        }

        int res = write(this->fd, buffer - sizelen, msglen + sizelen);

        if (res < 0 && run)
        {
            perror("Failed to send TCP packet");
        }

        return res;
    }

    int receive(char *buffer, int* offset)
    {
        unsigned short toread = read_14bit(this->fd);

        if (toread == 0)
        {
            printf("TCP connection to remote lost\n");
            return EXIT_FAILURE;
        }

        if (toread > MTU_SIZE)
        {
            printf("Incorrect size read from buffer, abandoning read.\n");
            return 0;
        }

        unsigned short readsize = toread;

        while (run && toread > 0)
        {
            ssize_t msglen = read(this->fd, buffer + (readsize - toread), toread);

            if (this->verbose && toread != msglen)
            {
                printf("Read partially, need %ld more bytes.\n", toread - msglen);
            }

            toread -= msglen;
        }

        if (this->verbose) printf("Received %zd bytes from remote\n", readsize);

        *offset = 0;
        return readsize;
    }

    int get_selectable()
    {
        return this->fd;
    }
};
