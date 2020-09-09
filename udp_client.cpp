#include "shared.cpp"

class udp_client : public transport_base
{
private:
    int fd;
    struct sockaddr_in remote_addr;

public:
    udp_client(struct sockaddr_in remote_addr)
        : remote_addr(remote_addr)
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
        int res = sendto(this->fd, (char*)buffer, msglen, 0, (const struct sockaddr *)&this->remote_addr, IP_SIZE);

        if (res < 0 && run)
        {
            perror("Failed to send UDP packet");
        }

        return res;
    }

    int receive(char *buffer)
    {
        socklen_t addrlen = IP_SIZE;
        ssize_t msglen = recvfrom(this->fd, (char*)buffer, MTU_SIZE, MSG_WAITALL, (struct sockaddr*)&this->remote_addr, &addrlen);

        if (msglen == -1)
        {
            if (run)
            {
                perror("Failed to read UDP packet");
            }

            return msglen;
        }

        if (this->verbose) printf("Received %zd bytes from remote\n", msglen);

        return msglen;
    }

    int get_selectable()
    {
        return this->fd;
    }
};
