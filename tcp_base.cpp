#pragma once
#include "shared.cpp"
#include "transport_base.cpp"

#if HAVE_TLS
    #include <openssl/ssl.h>
#endif

class tcp_base : virtual public transport_base
{
protected:
#if HAVE_TLS
    SSL_CTX *ssl_ctx;
    SSL *ssl;
#endif

public:
    int encoding = LENGTH_VAR;
    bool tls = false;

    inline unsigned short read_14bit(int fd)
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

            socklen_t msglen;
#if HAVE_TLS
            if (this->tls)
            {
                msglen = SSL_read(this->ssl, &current, sizeof(unsigned char));
            }
            else
            {
#endif
                msglen = read(fd, &current, sizeof(unsigned char));
#if HAVE_TLS
            }
#endif

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

    inline unsigned short read_16bit(int fd)
    {
        unsigned short size = 0;
        socklen_t msglen;

#if HAVE_TLS
        if (this->tls)
        {
            msglen = SSL_read(this->ssl, &size, sizeof(unsigned short));
        }
        else
        {
#endif
            msglen = read(fd, &size, sizeof(unsigned short));
#if HAVE_TLS
        }
#endif

        if (msglen == 0)
        {
            // propagate TCP closed event
            return 0;
        }

        if (msglen == 1)
        {
#if HAVE_TLS
            if (this->tls)
            {
                msglen = SSL_read(this->ssl, ((char*)&size) + 1, sizeof(unsigned char));
            }
            else
            {
#endif
                msglen = read(fd, ((char*)&size) + 1, sizeof(unsigned char));
#if HAVE_TLS
            }
#endif

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
            if (msglen > MTU_SIZE)
            {
                fprintf(stderr, "Refusing to send packet that is too large (%zd > MTU).\n", msglen);
                return 0;
            }

            if (this->encoding == LENGTH_VAR)
            {
                write_14bit(msglen, buffer, &sizelen);
            }
            else
            {
                write_16bit(msglen, buffer, &sizelen);
            }
        }

        int res;
#if HAVE_TLS
        if (this->tls)
        {
            res = SSL_write(this->ssl, buffer - sizelen, msglen + sizelen);
        }
        else
        {
#endif
            res = write(fd, buffer - sizelen, msglen + sizelen);
#if HAVE_TLS
        }
#endif

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
                printf("Incorrect size read from buffer (%d > MTU), abandoning connection.\n", toread);
                return 0;
            }

            readsize = toread;

            while (run && toread > 0)
            {
                ssize_t msglen;
#if HAVE_TLS
                if (this->tls)
                {
                    msglen = SSL_read(this->ssl, buffer + (readsize - toread), toread);
                }
                else
                {
#endif
                    msglen = read(fd, buffer + (readsize - toread), toread);
#if HAVE_TLS
                }
#endif

                if (this->verbose && toread != msglen)
                {
                    printf("Read partially, need %d more bytes.\n", (int)(toread - msglen));
                }

                toread -= msglen;
            }
        }
        else
        {
#if HAVE_TLS
            if (this->tls)
            {
                readsize = SSL_read(this->ssl, buffer, MTU_SIZE);
            }
            else
            {
#endif
                readsize = read(fd, buffer, MTU_SIZE);
#if HAVE_TLS
            }
#endif

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
    tcp_base(int encoding = LENGTH_VAR, bool tls = false)
        : encoding(encoding), tls(tls)
    {
#if HAVE_TLS
        if (this->tls)
        {
            SSL_library_init();
            SSL_load_error_strings();
        }
#endif
    }

#if HAVE_TLS
    void cleanup_ssl()
    {
        if (this->ssl != nullptr)
        {
            SSL_free(this->ssl);
            this->ssl = nullptr;
        }

        if (this->ssl_ctx != nullptr)
        {
            SSL_CTX_free(this->ssl_ctx);
            this->ssl_ctx = nullptr;
        }
    }
#endif
};
