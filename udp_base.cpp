#pragma once
#include "shared.cpp"

class udp_base : virtual public transport_base
{
public:
    inline int _send(int fd, const struct sockaddr *addr, char *buffer, ssize_t msglen)
    {
        int res = sendto(fd, buffer, msglen, 0, addr, IP_SIZE);

        if (res < 0 && run)
        {
            perror("Failed to send UDP packet");
        }

        return res;
    }

    inline int _receive(int fd, struct sockaddr *addr, char *buffer, int* offset)
    {
        socklen_t addrlen = IP_SIZE;
        ssize_t msglen = recvfrom(fd, buffer, MTU_SIZE, MSG_WAITALL, addr, &addrlen);

        if (msglen == -1)
        {
            if (run)
            {
                perror("Failed to read UDP packet");
            }

            return msglen;
        }

        if (this->verbose) printf("Received %zd bytes from remote\n", msglen);

        *offset = 0;
        return msglen;
    }
};
