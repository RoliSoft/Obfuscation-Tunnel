#pragma once
#include "shared.cpp"

class tcp_base : virtual public transport_base
{
public:
    bool omit_length = false;

    static inline unsigned short read_14bit(int fd)
    {
        int shift = 0;
        unsigned short value = 0;
        unsigned char current = 0;
        
        do
        {
            if (shift == 2 * 7) // cap at 16383
            {
                printf("Size header seems to be corrupted, abandoning read.\n");
                break;
            }

            socklen_t msglen = read(fd, &current, sizeof(unsigned char));

            if (msglen == 0)
            {
                // propagate TCP closed event
                return 0;
            }

            value |= (current & 0x7f) << shift;
            shift += 7;
        }
        while ((current & 0x80) != 0);

        return value;
    }

    static inline void write_14bit(unsigned short size, char* buffer, int* length)
    {
        *length = 0;
        unsigned short value = size;

        while (value >= 0x80)
        {
            buffer[(*length)++] = value | 0x80;
            value >>= 7;
        }

        buffer[(*length)++] = value;
    }

protected:
    inline int _send(int fd, char *buffer, ssize_t msglen)
    {
        int sizelen = 0;

        if (!this->omit_length)
        {
            write_14bit(msglen, buffer - sizeof(unsigned short), &sizelen);
            int sizediff = sizeof(unsigned short) - sizelen;

            if (sizediff == 1)
            {
                buffer[-1] = buffer[-2];
            }
        }

        int res = write(fd, buffer - sizelen, msglen + sizelen);

        if (res < 0 && run)
        {
            perror("Failed to send TCP packet");
        }

        return res;
    }

    inline int _receive(int fd, char *buffer, int* offset)
    {
        unsigned short readsize;

        if (!this->omit_length)
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

            readsize = toread;

            while (run && toread > 0)
            {
                ssize_t msglen = read(fd, buffer + (readsize - toread), toread);

                if (this->verbose && toread != msglen)
                {
                    printf("Read partially, need %ld more bytes.\n", toread - msglen);
                }

                toread -= msglen;
            }
        }
        else
        {
            readsize = read(fd, buffer, MTU_SIZE);
        }

        if (this->verbose) printf("Received %hu bytes from remote\n", readsize);

        *offset = 0;
        return readsize;
    }

protected:
    tcp_base(bool omit_length = false)
        : omit_length(omit_length)
    {
    }
};
