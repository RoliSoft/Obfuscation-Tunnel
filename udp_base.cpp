#pragma once
#include "shared.cpp"
#include "transport_base.cpp"
#include "tls_helpers.cpp"

class udp_base : virtual public transport_base
{
protected:
#if HAVE_TLS
    SSL_CTX *ssl_ctx;
    SSL *ssl;
#endif

public:
    bool tls = false;

protected:
    inline int _send(int fd, const struct sockaddr *addr, char *buffer, ssize_t msglen)
    {
        int res;

#if HAVE_TLS
        if (this->tls)
        {
            if (this->ssl == nullptr)
            {
                return -1;
            }

            res = SSL_write(this->ssl, buffer, msglen);
        }
        else
        {
#endif
            res = sendto(fd, buffer, msglen, 0, addr, IP_SIZE);
#if HAVE_TLS
        }
#endif

        if (res < 0 && run)
        {
            perror("Failed to send UDP packet");
        }

        return res;
    }

    inline int _receive(int fd, struct sockaddr *addr, char *buffer, int* offset)
    {
        socklen_t addrlen = IP_SIZE;
        ssize_t msglen;

#if HAVE_TLS
        if (this->tls)
        {
            if (this->ssl == nullptr)
            {
                return -1;
            }

            msglen = SSL_read(this->ssl, buffer, MTU_SIZE);
        }
        else
        {
#endif
            msglen = recvfrom(fd, buffer, MTU_SIZE, MSG_WAITALL, addr, &addrlen);
#if HAVE_TLS
        }
#endif

        if (msglen == -1)
        {
            if (run)
            {
                perror("Failed to read UDP packet");
            }

            return msglen;
        }

#if HAVE_TLS
        if (this->tls && msglen == 0)
        {
            if (SSL_get_shutdown(this->ssl) & SSL_RECEIVED_SHUTDOWN)
            {
                printf("DTLS connection shutdown received.\n");
                return -1;
            }
            
            int err = SSL_get_error(this->ssl, msglen);
            if (err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL)
            {
                printf("DTLS connection errored.\n");
                return -1;
            }

            return 0;
        }
#endif

        if (this->verbose) printf("Received %zd bytes from remote\n", msglen);

        *offset = 0;
        return msglen;
    }

    udp_base(bool tls = false)
        : tls(tls)
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
