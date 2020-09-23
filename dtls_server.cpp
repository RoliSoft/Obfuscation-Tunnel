#pragma once
#include "shared.cpp"
#if HAVE_TLS
#include "udp_base.cpp"
#include "tls_helpers.cpp"

class dtls_server : public udp_base
{
protected:
    int server_fd, client_fd;
    struct sockaddr_in local_addr, client_addr;
    char *cert_cn = nullptr, *cert_file = nullptr, *key_file = nullptr;
#if HAVE_TLS
    X509 *ssl_cert = nullptr;
    EVP_PKEY *ssl_key = nullptr;
#endif

public:
    dtls_server(struct sockaddr_in local_addr, struct session* session)
        : transport_base(session->verbose), udp_base(true), local_addr(local_addr), cert_cn(session->local_host), cert_file(session->tls_cert_file), key_file(session->tls_key_file)
    {
    }

    dtls_server(struct sockaddr_in local_addr, char *cert_cn = nullptr, char *cert_file = nullptr, char *key_file = nullptr, bool verbose = false)
        : transport_base(verbose), udp_base(true), local_addr(local_addr), cert_cn(cert_cn), cert_file(cert_file), key_file(key_file)
    {
    }

protected:
    int _accept()
    {
        if (!run)
        {
            return EXIT_FAILURE;
        }

        ERR_clear_error();
        const SSL_METHOD *method = DTLS_server_method();
        this->ssl_ctx = SSL_CTX_new(method);

        SSL_CTX_set_cookie_generate_cb(this->ssl_ctx, generate_cookie);
        SSL_CTX_set_cookie_verify_cb(this->ssl_ctx, verify_cookie);

        if (SSL_CTX_set_min_proto_version(this->ssl_ctx, DTLS1_2_VERSION) == 0)
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

		BIO* bio = BIO_new_dgram(this->server_fd, BIO_NOCLOSE);

	    struct timeval timeout;
		timeout.tv_sec = 5;
		timeout.tv_usec = 0;
		BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

        this->ssl = SSL_new(this->ssl_ctx);
        
		SSL_set_bio(this->ssl, bio, bio);
		SSL_set_options(this->ssl, SSL_OP_COOKIE_EXCHANGE);

        int res;
        while ((res = DTLSv1_listen(this->ssl, (BIO_ADDR*)&this->client_addr)) <= 0 && run);

        printf("Client connected via UDP from ");
        print_ip_port(&this->client_addr);
        printf("\n");

        if ((this->client_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        { 
            perror("Client socket creation failed");
            return EXIT_FAILURE;
        }

	    const int on = 1;
	    setsockopt(this->client_fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &on, (socklen_t) sizeof(on));
#if defined(SO_REUSEPORT) && !defined(__linux__)
	    setsockopt(this->client_fd, SOL_SOCKET, SO_REUSEPORT, (const void*) &on, (socklen_t) sizeof(on));
#endif

        if (bind(this->client_fd, (const struct sockaddr *)&this->local_addr, sizeof(this->local_addr)) < 0)
        {
            perror("Client bind failed");
            return EXIT_FAILURE;
        }

        if (connect(this->client_fd, (const struct sockaddr *)&this->client_addr, sizeof(this->client_addr)) < 0)
        {
            perror("Client connect failed");
            return EXIT_FAILURE;
        }

        bio = SSL_get_rbio(this->ssl);
        BIO_set_fd(bio, this->client_fd, BIO_NOCLOSE);
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &this->client_addr);

		timeout.tv_sec = 60;
		BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

        while ((res = SSL_accept(ssl)) <= 0 && run);
        if (res < 0)
        {
            fprintf(stderr, "Failed to initiate DTLS handshake.\n");
            ERR_print_errors_fp(stderr);

            close(this->client_fd);
            return EXIT_FAILURE;
        }

        const char *version = SSL_get_version(this->ssl);
        const char *cipher = SSL_get_cipher(this->ssl);
        printf("Established %s using %s.\n", version, cipher);

        sockets.push_back(this->client_fd);
        connected = true;

        return EXIT_SUCCESS;
    }

public:
    int start()
    {
        if ((this->server_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        { 
            perror("Server socket creation failed");
            return EXIT_FAILURE;
        }

	    const int on = 1;
	    setsockopt(this->server_fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &on, (socklen_t) sizeof(on));
#if defined(SO_REUSEPORT) && !defined(__linux__)
	    setsockopt(this->server_fd, SOL_SOCKET, SO_REUSEPORT, (const void*) &on, (socklen_t) sizeof(on));
#endif
        if (bind(this->server_fd, (const struct sockaddr *)&this->local_addr, sizeof(this->local_addr)) < 0)
        {
            perror("Bind failed");
            return EXIT_FAILURE;
        }

        printf("Started UDP server at ");
        print_ip_port(&this->local_addr);
        printf("\n");

        sockets.push_back(this->server_fd);
        started = true;

        if ((this->ssl_cert == nullptr || this->ssl_key == nullptr) && (this->cert_file == nullptr || this->key_file == nullptr))
        {
            printf("Generating temporary self-signed certificate for %s...\n", this->cert_cn);

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

        printf("Waiting for first client...\n");
        return _accept();
    }

    int restart()
    {
        close(this->client_fd);
        cleanup_ssl();

        printf("Waiting for next client...\n");
        return _accept();
    }

    int stop()
    {
        close(this->client_fd);
        close(this->server_fd);
        cleanup_ssl();

        started = false;
        connected = false;

        return EXIT_SUCCESS;
    }

    int disconnect()
    {
        printf("Dropping connected client.\n");
        close(this->client_fd);

        connected = false;

        return EXIT_SUCCESS;
    }

    int send(char *buffer, ssize_t msglen)
    {
        if (!this->connected)
        {
            return 0;
        }

        int res = _send(this->client_fd, (const struct sockaddr*)&this->client_addr, buffer, msglen);

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

        int res = _receive(this->client_fd, (struct sockaddr*)&this->client_addr, buffer, offset);

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
#endif
