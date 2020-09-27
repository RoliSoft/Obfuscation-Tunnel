#pragma once
#include "shared.cpp"
#include "udp_base.cpp"
#include "tls_helpers.cpp"

class udp_client : public udp_base
{
protected:
    int fd;
    struct sockaddr_in remote_addr;
    char *tls_remote_host;
    bool tls_no_verify = false;
    char *tls_ca_path = nullptr;

public:
    udp_client(struct sockaddr_in remote_addr, bool tls, struct session* session)
        : transport_base(session->verbose), udp_base(tls), remote_addr(remote_addr), tls_remote_host(session->remote_host), tls_no_verify(session->tls_no_verify), tls_ca_path(session->tls_ca_bundle)
    {
    }

    udp_client(struct sockaddr_in remote_addr, bool tls = false, char* tls_remote_host = nullptr, bool tls_no_verify = false, char *tls_ca_path = nullptr, bool verbose = false)
        : transport_base(verbose), udp_base(tls), remote_addr(remote_addr), tls_remote_host(tls_remote_host), tls_no_verify(tls_no_verify), tls_ca_path(tls_ca_path)
    {
    }

private:
#if HAVE_TLS
    int _handshake()
    {
        int res = connect(fd, (const struct sockaddr*)&this->remote_addr, IP_SIZE);
        if (res == -1)
        {
            perror("Failed to connect to remote host");
            return EXIT_FAILURE;
        }

        ERR_clear_error();
        const SSL_METHOD *method = DTLS_client_method();
        this->ssl_ctx = SSL_CTX_new(method);

        if (SSL_CTX_set_min_proto_version(this->ssl_ctx, DTLS1_2_VERSION) == 0)
        {
            fprintf(stderr, "Failed to set DTLS minimum version: ");
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

        if ((res = SSL_connect(this->ssl)) == -1)
        {
            fprintf(stderr, "Failed to initiate DTLS handshake: ");

            int reason = ERR_GET_REASON(ERR_peek_error());
            bool fatal = false;
            switch (reason)
            {
                default:
                    ERR_print_errors_fp(stderr);
                    break;
                
                case 0:
                    printf("Failed to send packet.\n");
                    break;
                
                case SSL_R_CERTIFICATE_VERIFY_FAILED:
                    fprintf(stderr, "certificate verification failed.\n");
                    fatal = true;
                    break;
                
                case SSL_R_WRONG_VERSION_NUMBER:
                    fprintf(stderr, "endpoint not DTLS-enabled or unsupported version.\n");
                    fatal = true;
                    break;
            }

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

        return EXIT_SUCCESS;
    }
#endif

public:
#if HAVE_TLS
    int restart()
    {
        if (this->tls)
        {
            cleanup_ssl();
            printf("Retrying DTLS handshake...\n");
            return _handshake();
        }
        else
        {
            return EXIT_SUCCESS;
        }
    }
#endif

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

#if HAVE_TLS
        if (this->tls)
        {
            printf("Performing DTLS handshake...\n");

            if (_handshake() != EXIT_SUCCESS)
            {
                return EXIT_FAILURE;
            }
        }
#endif

        sockets.push_back(this->fd);
        started = true;

        return EXIT_SUCCESS;
    }

    int stop()
    {
        close(this->fd);
#if HAVE_TLS
        if (this->tls) cleanup_ssl();
#endif

        started = false;

        return EXIT_SUCCESS;
    }

    int send(char *buffer, ssize_t msglen)
    {
        return _send(this->fd, (const struct sockaddr*)&this->remote_addr, buffer, msglen);
    }

    int receive(char *buffer, int* offset)
    {
        return _receive(this->fd, (struct sockaddr*)&this->remote_addr, buffer, offset);
    }

    int get_selectable()
    {
        return this->fd;
    }
};
