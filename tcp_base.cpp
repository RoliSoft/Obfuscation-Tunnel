#pragma once
#include "shared.cpp"
#include "transport_base.cpp"

class tcp_base : virtual public transport_base
{
public:
    int encoding = LENGTH_VAR;

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
        int len = sizeof(unsigned short);

        while (value >= 0x80)
        {
            buffer[-len + (*length)++] = value | 0x80;
            value >>= 7;
        }

        buffer[-len + (*length)++] = value;

        int sizediff = len - *length;

        if (sizediff == 1)
        {
            buffer[-1] = buffer[-2];
        }
    }

    static inline unsigned short read_16bit(int fd)
    {
        unsigned short size = 0;
        socklen_t msglen = read(fd, &size, sizeof(unsigned short));

        if (msglen == 0)
        {
            // propagate TCP closed event
            return 0;
        }

        if (msglen == 1)
        {
            msglen = read(fd, ((char*)&size) + 1, sizeof(unsigned char));

            if (msglen == 0)
            {
                // propagate TCP closed event
                return 0;
            }
        }

        return ntohs(size);
    }

    static inline void write_16bit(unsigned short size, char* buffer, int* length)
    {
        *length = sizeof(unsigned short);
        *((unsigned short*)&(buffer - *length)[0]) = htons(size);
    }

protected:
    inline int _send(int fd, char *buffer, ssize_t msglen)
    {
        int sizelen = 0;

        if (this->encoding != LENGTH_NONE)
        {
            if (this->encoding == LENGTH_VAR)
            {
                write_14bit(msglen, buffer, &sizelen);
            }
            else
            {
                write_16bit(msglen, buffer, &sizelen);
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
        int readsize;

        if (this->encoding != LENGTH_NONE)
        {
            unsigned short toread = this->encoding == LENGTH_VAR
                ? read_14bit(fd)
                : read_16bit(fd);

            if (toread == 0)
            {
                printf("TCP connection to remote lost\n");
                return -1;
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
                    printf("Read partially, need %d more bytes.\n", (int)(toread - msglen));
                }

                toread -= msglen;
            }
        }
        else
        {
            readsize = read(fd, buffer, MTU_SIZE);

            if (readsize < 1)
            {
                printf("TCP connection to remote lost\n");
                return -1;
            }
        }

        if (this->verbose) printf("Received %d bytes from remote\n", readsize);

        *offset = 0;
        return readsize;
    }

protected:
    tcp_base(int encoding = LENGTH_VAR)
        : encoding(encoding)
    {
    }
};
