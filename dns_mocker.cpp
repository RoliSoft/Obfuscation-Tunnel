#pragma once
#include "shared.cpp"
#include "mocker_base.cpp"
#include "udp_server.cpp"
#include "udp_client.cpp"
#include "tcp_server.cpp"
#include "tcp_client.cpp"

struct dns_packet_header
{
    unsigned short transaction_id;
    unsigned short flags;
    unsigned short questions;
    unsigned short answer_rrs;
    unsigned short authority_rrs;
    unsigned short additional_rrs;
    // beginning of query 1
    unsigned char length;
    // beginning of data forced as domain name
} __attribute__((packed));

struct dns_packet_footer
{
    unsigned char terminator;
    unsigned short type;
    unsigned short q_class;
    // end of query 1
} __attribute__((packed));

class dns_mocker : virtual public mocker_base
{
private:
    struct dns_packet_header header;
    struct dns_packet_footer footer;

public:
    dns_mocker(bool server)
        : mocker_base(server)
    {
        memset(&this->header, 0, sizeof(this->header));
        this->header.transaction_id = htons(0x1337);
        this->header.flags = server ? htons(0x8180) : htons(0x0100); // server ? answer : question
        this->header.questions = htons(0x0001);

        memset(&this->footer, 0, sizeof(this->footer));
        this->footer.type = htons(0x0001); // type A
        this->footer.q_class = htons(0x0001);

        printf("Encapsulating packets into DNS %s.\n", this->server ? "replies" : "queries");
    }

    dns_mocker(struct session* session)
        : dns_mocker(strcmp(session->mocker, "dns_server") == 0)
    {
    }

    virtual int setup(transport_base *local, transport_base *remote)
    {
        if (this->server)
        {
            tcp_server* tcp = dynamic_cast<tcp_server*>(local);
            if (tcp != nullptr)
            {
                printf("Overriding TCP transport settings to match length encoding of DNS packets.\n");

                tcp->encoding = LENGTH_16BIT;

                return EXIT_SUCCESS;
            }

            udp_server* udp = dynamic_cast<udp_server*>(local);
            if (udp == nullptr)
            {
                printf("The dns_server module requires UDP or TCP local to function properly.\n");
                return EXIT_SUCCESS;
            }

            return EXIT_SUCCESS;
        }
        else
        {
            tcp_client* tcp = dynamic_cast<tcp_client*>(remote);
            if (tcp != nullptr)
            {
                printf("Overriding TCP transport settings to match length encoding of DNS packets.\n");

                tcp->encoding = LENGTH_16BIT;

                return EXIT_SUCCESS;
            }

            udp_client* udp = dynamic_cast<udp_client*>(remote);
            if (udp == nullptr)
            {
                printf("The dns_client module requires UDP or TCP remote to function properly.\n");
                return EXIT_SUCCESS;
            }

            return EXIT_SUCCESS;
        }
    }

    virtual int encapsulate(char* message, int length, int* offset)
    {
        this->header.length = (unsigned char)min(length, UCHAR_MAX);
        return _encapsulate(message, length, offset, (char*)&this->header, sizeof(this->header), (char*)&this->footer, sizeof(this->footer));
    }

    virtual int decapsulate(char* message, int length, int* offset)
    {
        return _decapsulate(message, length, offset, sizeof(this->header), sizeof(this->footer));
    }
};
