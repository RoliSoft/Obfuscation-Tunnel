#pragma once
#include "shared.cpp"
#include "tcp_base.cpp"
#include "tls_helpers.cpp"

class tcp_server : public tcp_base
{
private:
    int server_fd, client_fd;
    struct sockaddr_in local_addr, client_addr;
    char *cert_cn = nullptr, *cert_file = nullptr, *key_file = nullptr;
#if HAVE_TLS
    X509 *ssl_cert = nullptr;
    EVP_PKEY *ssl_key = nullptr;
#endif

public:
    tcp_server(struct sockaddr_in local_addr, bool tls, struct session* session)
        : transport_base(session->verbose), tcp_base(session->length_type, tls), local_addr(local_addr), cert_cn(session->tls_host), cert_file(session->tls_cert_file), key_file(session->tls_key_file)
    {
    }

    tcp_server(struct sockaddr_in local_addr, int encoding = LENGTH_VAR, bool tls = false, char *cert_cn = nullptr, char *cert_file = nullptr, char *key_file = nullptr, bool verbose = false)
        : transport_base(verbose), tcp_base(encoding, tls), local_addr(local_addr), cert_cn(cert_cn), cert_file(cert_file), key_file(key_file)
    {
    }

private:
    int _accept()
    {
        if (!run)
        {
            return EXIT_FAILURE;
        }

        socklen_t addrlen;
        this->client_fd = accept(this->server_fd, (struct sockaddr*)&this->client_addr, &addrlen);

        if (this->client_fd < 0)
        {
            if (run)
            {
                perror("Failed to accept incoming connection");
                return EXIT_FAILURE;
            }
            else
            {
                return EXIT_SUCCESS;
            }
        }

        printf("Client connected via TCP from ");
        print_ip_port(&this->client_addr);
        printf("\n");

#if HAVE_TLS
        if (this->tls)
        {
            ERR_clear_error();
            const SSL_METHOD *method = TLS_server_method();
            this->ssl_ctx = SSL_CTX_new(method);

            if (SSL_CTX_set_min_proto_version(this->ssl_ctx, TLS1_2_VERSION) == 0)
            {
                fprintf(stderr, "Failed to set TLS minimum version: ");
                ERR_print_errors_fp(stderr);
            }

            if (SSL_CTX_use_certificate(this->ssl_ctx, this->ssl_cert) <= 0)
            {
                fprintf(stderr, "Failed to load certificate: ");
                ERR_print_errors_fp(stderr);
                return EXIT_FAILURE;
            }
            
            if (SSL_CTX_use_PrivateKey(this->ssl_ctx, this->ssl_key) <= 0)
            {
                fprintf(stderr, "Failed to load private key: ");
                ERR_print_errors_fp(stderr);
                return EXIT_FAILURE;
            }

            if (!SSL_CTX_check_private_key(this->ssl_ctx))
            {
                fprintf(stderr, "Private key does not match the certificate public key.\n");
                return EXIT_FAILURE;
            }

            int res;
            this->ssl = SSL_new(this->ssl_ctx);
            SSL_set_fd(this->ssl, this->client_fd);
            if ((res = SSL_accept(this->ssl)) == -1)
            {
                fprintf(stderr, "Failed to initiate TLS handshake: ");

                int reason = ERR_GET_REASON(ERR_peek_error());
                bool fatal = false;
                switch (reason)
                {
                    default:
                        ERR_print_errors_fp(stderr);
                        break;
                    
                    case SSL_R_WRONG_VERSION_NUMBER:
                        fprintf(stderr, "client not TLS-enabled or unsupported version.\n");
                        fatal = true;
                        break;
                }

                close(this->client_fd);
                cleanup_ssl();
                return EXIT_FAILURE;
            }

            const char *version = SSL_get_version(this->ssl);
            const char *cipher = SSL_get_cipher(this->ssl);
            printf("Established %s using %s.\n", version, cipher);
        }
#endif

        sockets.push_back(this->client_fd);
        connected = true;

        int i = 1;
        setsockopt(this->client_fd, IPPROTO_TCP, TCP_NODELAY, (void *)&i, sizeof(i));
#ifdef TCP_QUICKACK
        setsockopt(this->client_fd, IPPROTO_TCP, TCP_QUICKACK, (void *)&i, sizeof(i));
#endif

        return EXIT_SUCCESS;
    }

public:
    int start()
    {
        if ((this->server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        { 
            perror("Server socket creation failed");
            return EXIT_FAILURE;
        }

        if (bind(this->server_fd, (const struct sockaddr *)&this->local_addr, sizeof(this->local_addr)) < 0)
        {
            perror("Bind failed");
            return EXIT_FAILURE;
        }

        if (listen(this->server_fd, 1) != 0)
        {
            perror("Failed to listen on local port");
            return EXIT_FAILURE;
        }

        printf("Started TCP server at ");
        print_ip_port(&this->local_addr);
        printf("\n");

        sockets.push_back(this->server_fd);
        started = true;

#if HAVE_TLS
        if (this->tls)
        {
            if ((this->ssl_cert == nullptr || this->ssl_key == nullptr) && (this->cert_file == nullptr || this->key_file == nullptr))
            {
                printf("Generating temporary self-signed certificate for this session...\n");

                if (ssl_gen_cert(this->cert_cn == nullptr ? TLS_DEFAULT_CN : this->cert_cn, &this->ssl_cert, &this->ssl_key) != EXIT_SUCCESS)
                {
                    fprintf(stderr, "Failed to generate certificate: ");
                    ERR_print_errors_fp(stderr);
                    return EXIT_FAILURE;
                }

                printf("Fingerprint of certificate is ");
                print_cert_hash(this->ssl_cert);
                printf("\n");
            }
            else
            {
                FILE *fp = fopen(this->cert_file, "r");
                if (!fp)
                {
                    fprintf(stderr, "Failed to open certificate file '%s'.'\n", this->cert_file);
                    return EXIT_FAILURE;
                }

                this->ssl_cert = PEM_read_X509(fp, NULL, NULL, NULL);
                if (!this->ssl_cert) {
                    fprintf(stderr, "Failed to parse certificate file '%s'.\n", this->cert_file);
                    fclose(fp);
                    return EXIT_FAILURE;
                }

                fclose(fp);
                
                fp = fopen(this->key_file, "r");
                if (!fp)
                {
                    fprintf(stderr, "Failed to open private key file '%s'.'\n", this->key_file);
                    return EXIT_FAILURE;
                }

                this->ssl_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
                if (!this->ssl_key) {
                    fprintf(stderr, "Failed to parse private key file '%s'.\n", this->key_file);
                    fclose(fp);
                    return EXIT_FAILURE;
                }

                fclose(fp);

                char name[256], issuer[256];
                X509_NAME_get_text_by_NID(X509_get_subject_name(this->ssl_cert), NID_commonName, (char*)&name, sizeof(name));

                X509_NAME *_issuer = X509_get_issuer_name(this->ssl_cert);
                if (_issuer != NULL) X509_NAME_get_text_by_NID(_issuer, NID_commonName, (char*)&issuer, sizeof(issuer));

                printf("Loaded certificate for %s, issued by %s.\n", name, issuer);
            }
        }
#endif

        printf("Waiting for first client...\n");
        return _accept();
    }

    int restart()
    {
        close(this->client_fd);
#if HAVE_TLS
        if (this->tls) cleanup_ssl();
#endif

        printf("Waiting for next client...\n");
        return _accept();
    }

    int stop()
    {
        close(this->client_fd);
        close(this->server_fd);
#if HAVE_TLS
        if (this->tls) cleanup_ssl();
#endif

        started = false;
        connected = false;

        return EXIT_SUCCESS;
    }

    int disconnect()
    {
        printf("Dropping connected client.\n");
        close(this->client_fd);
#if HAVE_TLS
        if (this->tls) cleanup_ssl();
#endif

        connected = false;

        return EXIT_SUCCESS;
    }

    int send(char *buffer, ssize_t msglen)
    {
        if (!this->connected)
        {
            return 0;
        }

        int res = _send(this->client_fd, buffer, msglen);

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

        int res = _receive(this->client_fd, buffer, offset);

        if (res < 0)
        {
            this->connected = false;
        }

        return res;
    }

    int get_selectable()
    {
        return this->client_fd;
    }
};
