#pragma once
#include "shared.cpp"
#include "mocker_base.cpp"
#include "tcp_client.cpp"

struct socks5_auth
{
    unsigned char version;
    unsigned char count;
    unsigned char auth_1;
} __attribute__((packed));

struct socks5_auth_resp
{
    unsigned char version;
    unsigned char accepted; // should be 0, 255 if failed
} __attribute__((packed));

struct socks5_connect
{
    unsigned char version;
    unsigned char command;
    unsigned char reserved;
    unsigned char type;
    unsigned int addr;
    unsigned short port;
} __attribute__((packed));

struct socks5_connect_resp
{
    unsigned char version;
    unsigned char result; // should be 0
    unsigned char reserved;
    unsigned char type;
    unsigned int addr;
    unsigned short port;
} __attribute__((packed));

class socks5_proxy : virtual public mocker_base
{
private:
    struct socks5_auth auth;
    struct socks5_connect connect;

protected:
    char *config;
    struct sockaddr_in remote_addr, proxy_addr;
    bool tls;
    int encoding;

public:
    socks5_proxy(char *config)
        : mocker_base(false, true, false), config(config)
    {
        memset(&this->auth, 0, sizeof(this->auth));
        this->auth.version = 5; // version 5
        this->auth.count = 1;   // 1 auth accepted
        this->auth.auth_1 = 0;  // no authentication

        memset(&this->connect, 0, sizeof(this->connect));
        this->connect.version = 5; // version 5
        this->connect.command = 1; // 1 -- connect
        this->connect.type = 1;    // 1 -- ipv4
    }

    socks5_proxy(struct session* session)
        : socks5_proxy(session->mocker)
    {
    }

    virtual int setup(transport_base *local, transport_base *remote)
    {
        (void)local;

        tcp_client* tcp = dynamic_cast<tcp_client*>(remote);
        if (tcp == nullptr)
        {
            fprintf(stderr, "The socks5_proxy module requires TCP remote to function.\n");
            return EXIT_FAILURE;
        }

        if (parse_endpoint_arg(this->config, nullptr, nullptr, &this->proxy_addr) != EXIT_SUCCESS)
        {
            fprintf(stderr, "Failed to parse SOCKSv5 arguments, aborting connection.\n");
            return EXIT_FAILURE;
        }

        this->remote_addr = tcp->remote_addr;
        this->tls = tcp->tls;
        tcp->remote_addr = this->proxy_addr;
        tcp->tls_delay = true;

        return EXIT_SUCCESS;
    }

    virtual int handshake(transport_base *local, transport_base *remote)
    {
        (void)local;

        tcp_client* tcp = dynamic_cast<tcp_client*>(remote);
        int original_encoding = tcp->encoding;
        bool original_verbose = tcp->verbose;
        tcp->encoding = LENGTH_NONE;
        tcp->verbose = false;

        printf("Connecting via SOCKSv5 proxy to ");
        print_ip_port(&this->remote_addr);
        printf("... ");
        fflush(stdout);

        int length, offset;
        length = tcp->send((char*)&this->auth, sizeof(this->auth));

        if (length == 0)
        {
            fprintf(stderr, "Connection interrupted during handshake.\n");
            goto fail;
        }

        struct socks5_auth_resp auth_resp;
        length = tcp->receive((char*)&auth_resp, &offset);

        if (length != sizeof(auth_resp))
        {
            fprintf(stderr, "Connection interrupted during handshake.\n");
            goto fail;
        }
        
        if (auth_resp.version != 5)
        {
            fprintf(stderr, "Incorrect version number sent by SOCKSv5 server: %d\n", auth_resp.version);
            goto fail;
        }
        
        if (auth_resp.accepted != 0)
        {
            fprintf(stderr, "SOCKSv5 server requires authentication.\n");
            goto fail;
        }

        this->connect.addr = *(unsigned int*)&this->remote_addr.sin_addr;
        this->connect.port = this->remote_addr.sin_port;

        length = tcp->send((char*)&this->connect, sizeof(this->connect));

        if (length == 0)
        {
            fprintf(stderr, "Connection interrupted during handshake.\n");
            goto fail;
        }

        struct socks5_connect_resp connect_resp;
        length = tcp->receive((char*)&connect_resp, &offset);

        if (length != sizeof(connect_resp))
        {
            fprintf(stderr, "Connection interrupted during handshake.\n");
            goto fail;
        }
        
        if (connect_resp.result != 0)
        {
            fprintf(stderr, "SOCKSv5 server failed to connect with error number: %d\n", connect_resp.result);
            goto fail;
        }

        printf("Connected.\n");

        tcp->encoding = original_encoding;
        tcp->verbose = original_verbose;

#if HAVE_TLS
        if (this->tls)
        {
            if (tcp->_do_tls() != EXIT_SUCCESS)
            {
                goto fail;
            }
        }
#endif

        return EXIT_SUCCESS;

fail:
        tcp->stop();
        tcp->encoding = original_encoding;
        tcp->verbose = original_verbose;
        return EXIT_FAILURE;
    }
};
