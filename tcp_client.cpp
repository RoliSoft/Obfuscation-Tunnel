#pragma once
#include "shared.cpp"
#include "tcp_base.cpp"
#include "tls_helpers.cpp"

class tcp_client : public tcp_base
{
    friend class socks5_proxy;

private:
    int fd;
    struct sockaddr_in remote_addr;
    char *tls_remote_host;
    bool tls_no_verify = false;
    char *tls_ca_path = nullptr;
    bool tls_delay = false;

public:
    tcp_client(struct sockaddr_in remote_addr, bool tls, struct session* session)
        : transport_base(session->verbose), tcp_base(session->length_type, tls), remote_addr(remote_addr), tls_remote_host(session->remote_host), tls_no_verify(session->tls_no_verify), tls_ca_path(session->tls_ca_bundle)
    {
    }

    tcp_client(struct sockaddr_in remote_addr, int encoding = LENGTH_VAR, bool tls = false, char* tls_remote_host = nullptr, bool tls_no_verify = false, char *tls_ca_path = nullptr, bool verbose = false)
        : transport_base(verbose), tcp_base(encoding, tls), remote_addr(remote_addr), tls_remote_host(tls_remote_host), tls_no_verify(tls_no_verify), tls_ca_path(tls_ca_path)
    {
    }

private:
#if HAVE_TLS
    int _do_tls()
    {
        ERR_clear_error();
        const SSL_METHOD *method = TLS_client_method();
        this->ssl_ctx = SSL_CTX_new(method);

        if (SSL_CTX_set_min_proto_version(this->ssl_ctx, TLS1_2_VERSION) == 0)
        {
            fprintf(stderr, "Failed to set TLS minimum version: ");
            ERR_print_errors_fp(stderr);
        }

        if (!this->tls_no_verify)
        {
            SSL_CTX_set_verify(this->ssl_ctx, SSL_VERIFY_PEER, NULL);

            if (this->tls_ca_path == nullptr)
            {
                if (SSL_CTX_set_default_verify_paths(this->ssl_ctx) == 0)
                {
                    fprintf(stderr, "Failed to load system-default CA certificate bundle.\n");
                    return EXIT_FAILURE;
                }
            }
            else
            {
                if (SSL_CTX_load_verify_locations(this->ssl_ctx, this->tls_ca_path, NULL) == 0)
                {
                    fprintf(stderr, "Failed to load specified CA certificate bundle.\n");
                    return EXIT_FAILURE;
                }
            }
        }

        this->ssl = SSL_new(this->ssl_ctx);
        SSL_set_fd(this->ssl, this->fd);

        if (!this->tls_no_verify)
        {
            SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
            if (tls_remote_host == nullptr || !SSL_set1_host(this->ssl, this->tls_remote_host))
            {
                fprintf(stderr, "Failed to set hostname for TLS validation: ");
                ERR_print_errors_fp(stderr);
                return EXIT_FAILURE;
            }
        }

        int res;
        if ((res = SSL_connect(this->ssl)) == -1)
        {
            fprintf(stderr, "Failed to initiate TLS handshake: ");

            int reason = ERR_GET_REASON(ERR_peek_error());
            switch (reason)
            {
                default:
                    ERR_print_errors_fp(stderr);
                    break;
                
                case SSL_R_CERTIFICATE_VERIFY_FAILED:
                    fprintf(stderr, "certificate verification failed.\n");
                    //fatal = true;
                    break;
                
                case SSL_R_WRONG_VERSION_NUMBER:
                    fprintf(stderr, "endpoint not TLS-enabled or unsupported version.\n");
                    //fatal = true;
                    break;
            }

            close(this->fd);
            cleanup_ssl();
            return EXIT_FAILURE;
        }

        char name[256];
        X509* cert = SSL_get_peer_certificate(this->ssl);
        X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, (char*)&name, sizeof(name));

        const char *version = SSL_get_version(this->ssl);
        const char *cipher = SSL_get_cipher(this->ssl);
        printf("Established %s with %s using %s.\n", version, name, cipher);

        if (this->tls_no_verify)
        {
            printf("Fingerprint of certificate is ");
            print_cert_hash(cert);
            printf("\n");
        }
        
        X509_free(cert);

        this->tls = true;

        return EXIT_SUCCESS;
    }
#endif

    int _connect()
    {
        if (!run)
        {
            return EXIT_FAILURE;
        }

        if (this->tls_delay)
        {
            this->tls = false;
        }

        int res;
        do
        {
            if ((this->fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
            { 
                perror("Client socket creation failed");
                return EXIT_FAILURE;
            }

            res = connect(this->fd, (const struct sockaddr *)&this->remote_addr, IP_SIZE);

            if (res == -1)
            {
                if (!run)
                {
                    return EXIT_FAILURE;
                }
                
                if (errno == ECONNREFUSED)
                {
                    close(this->fd);
                    sleep(1);
                    continue;
                }
                else
                {
                    perror("Failed to connect to remote host");
                    return EXIT_FAILURE;
                }
            }

            printf("Connected.\n");

#if HAVE_TLS
            if (this->tls)
            {
                if (_do_tls() != EXIT_SUCCESS)
                {
                    return EXIT_FAILURE;
                }

                res = 0;
            }
#endif
        }
        while (res != 0 && run);

        sockets.push_back(this->fd);
        started = true;
        connected = true;

        int i = 1;
        setsockopt(this->fd, IPPROTO_TCP, TCP_NODELAY, (void *)&i, sizeof(i));
#ifdef TCP_QUICKACK
        setsockopt(this->fd, IPPROTO_TCP, TCP_QUICKACK, (void *)&i, sizeof(i));
#endif

        return EXIT_SUCCESS;
    }

public:
    int start()
    {
        printf("Connecting via TCP to ");
        print_ip_port(&this->remote_addr);
        printf("... ");
        fflush(stdout);

        return _connect();
    }

    int restart()
    {
        close(this->fd);
#if HAVE_TLS
        if (this->tls) cleanup_ssl();
#endif

        printf("Reconnecting via TCP to ");
        print_ip_port(&this->remote_addr);
        printf("... ");
        fflush(stdout);

        return _connect();
    }

    int stop()
    {
        close(this->fd);
#if HAVE_TLS
        if (this->tls) cleanup_ssl();
#endif

        started = false;
        connected = false;

        return EXIT_SUCCESS;
    }

    int send(char *buffer, ssize_t msglen)
    {
        if (!this->connected)
        {
            return 0;
        }

        int res = _send(this->fd, buffer, msglen);

        if (res < 0)
        {
            this->connected = false;
        }

        return res;
    }

    int receive(char *buffer, int* offset)
    {
        if (!this->connected)
        {
            return 0;
        }

        int res = _receive(this->fd, buffer, offset);

        if (res < 0)
        {
            this->connected = false;
        }

        return res;
    }

    int get_selectable()
    {
        return this->fd;
    }
};
