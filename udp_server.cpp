#include "shared.cpp"

class udp_server : public transport_base
{
private:
    int fd;
    struct sockaddr_in local_addr, client_addr;

public:
    udp_server(struct sockaddr_in local_addr)
        : local_addr(local_addr)
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

        int res = sendto(this->fd, (char*)buffer, msglen, 0, (const struct sockaddr *)&this->client_addr, IP_SIZE);

        if (res < 0 && run)
        {
            perror("Failed to send UDP packet");
        }

        return res;
    }

    int receive(char *buffer, int* offset)
    {
        socklen_t addrlen = IP_SIZE;
        ssize_t msglen = recvfrom(this->fd, (char*)buffer, MTU_SIZE, MSG_WAITALL, (struct sockaddr*)&this->client_addr, &addrlen);

        if (msglen == -1)
        {
            if (run)
            {
                perror("Failed to read UDP packet");
            }

            return msglen;
        }

        if (!this->connected)
        {
            this->connected = 1;

            printf("Client connected via UDP from ");
            print_ip_port(&this->client_addr);
            printf("\n");
        }

        if (this->verbose) printf("Received %zd bytes from client\n", msglen);

        *offset = 0;
        return msglen;
    }

    int get_selectable()
    {
        return this->fd;
    }
};
