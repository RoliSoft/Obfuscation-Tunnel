#pragma once
#include "shared.cpp"

class tcp_base : public transport_base
{
public:
    int _send(int fd, char *buffer, ssize_t msglen)
    {
        int sizelen = 0;
        write_14bit(msglen, buffer - sizeof(unsigned short), &sizelen);
        int sizediff = sizeof(unsigned short) - sizelen;

        if (sizediff == 1)
        {
            buffer[-1] = buffer[-2];
        }

        int res = write(fd, buffer - sizelen, msglen + sizelen);

        if (res < 0 && run)
        {
            perror("Failed to send TCP packet");
        }

        return res;
    }

    int _receive(int fd, char *buffer, int* offset)
    {
        unsigned short toread = read_14bit(fd);

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
            ssize_t msglen = read(fd, buffer + (readsize - toread), toread);

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
};
