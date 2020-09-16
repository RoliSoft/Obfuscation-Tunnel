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

struct dns_packet_answer_footer
{
    struct dns_packet_footer question;
    // beginning of answer 1
    unsigned short name_ref;
    unsigned short type;
    unsigned short q_class;
    unsigned int ttl;
    unsigned short length;
    unsigned int address;
    // end of answer 1
} __attribute__((packed));

class dns_mocker : virtual public mocker_base
{
private:
    struct dns_packet_header header;
    struct dns_packet_footer footer;
    struct dns_packet_answer_footer answer_footer;

public:
    bool fragment;
    char* domain;
    int domain_len = 0;

    dns_mocker(bool server, bool fragment, char *domain)
        : mocker_base(server, false, true), fragment(fragment), domain(domain)
    {
        memset(&this->header, 0, sizeof(this->header));
        this->header.transaction_id = htons(0x1337);
        this->header.flags = server ? htons(0x8180) : htons(0x0100); // server ? answer : question
        this->header.questions = htons(0x0001);

        memset(&this->footer, 0, sizeof(this->footer));
        this->footer.type = htons(0x0001); // type A
        this->footer.q_class = htons(0x0001);

        memset(&this->answer_footer, 0, sizeof(this->answer_footer));
        this->answer_footer.question = this->footer;
        this->answer_footer.name_ref = htons(0xc00c); // 0xc00c references the 12th byte in the header which is this->header.length
        this->answer_footer.type = htons(0x0001);
        this->answer_footer.q_class = htons(0x0001);
        this->answer_footer.ttl = htonl(0x0000012c);
        this->answer_footer.length = htons(0x0004);
        this->answer_footer.address = htonl(0x01010101);

        if (domain != nullptr && domain[0] != 0)
        {
            this->domain_len = strlen(domain) + 1;
            this->domain = (char*)malloc(this->domain_len);
            memcpy(this->domain + 1, domain, this->domain_len);
            this->domain[0] = '.';

            if (this->domain[this->domain_len - 1] == '.') this->domain_len--;

            int i = 0, last = 0;
            for (; i < this->domain_len; i++)
            {
                if (this->domain[i] != '.' || i == 0) continue;
                this->domain[last] = i - last - 1;
                last = i;
            }

            this->domain[last] = i - last - 1;
        }

        printf("Encapsulating packets into DNS %s.\n", this->server ? "replies" : "queries");

        if (this->fragment)
        {
            printf("Encoding and fragmenting DNS labels for compatibility with binary data.\n");
        }

        if (this->domain_len != 0)
        {
            printf("Acting as authoritative resolver for domain %s.\n", domain);
        }
    }

    dns_mocker(struct session* session)
        : dns_mocker(strcmp(session->mocker, "dns_server") == 0, session->fragment, session->domain)
    {
    }

    static int base32_decode(const uint8_t *encoded, uint8_t *result, int bufSize)
    {
        int buffer = 0;
        int bitsLeft = 0;
        int count = 0;

        for (int i = 0, fragment = 0; count < bufSize && encoded[i]; i++, fragment++)
        {
            if (fragment != 0 && fragment % 60 == 0)
            {
                printf("flag %d %d\n", i, fragment);
                fragment = -1;
                continue;
            }

            uint8_t ch = encoded[i];
            if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '-')
            {
                continue;
            }
            buffer <<= 5;

            if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')) {
                ch = (ch & 0x1F) - 1;
            } else if (ch >= '2' && ch <= '7') {
                ch -= '2' - 26;
            } else {
                printf("errpos %d\n", i);
                fprintf(stderr, "Invalid character 0x%02hhx in base-32 string.\n", ch);
                return -1;
            }

            buffer |= ch;
            bitsLeft += 5;

            if (bitsLeft >= 8)
            {
                result[count++] = buffer >> (bitsLeft - 8);
                bitsLeft -= 8;
            }
        }

        if (count < bufSize) {
            result[count] = '\000';
        }

        return count;
    }

    static int base32_encode(const uint8_t *data, int length, uint8_t *result, int bufSize)
    {
        int count = 0;
        int lastFlag = -1;
        int flagCount = 0;

        if (length > 0)
        {
            int buffer = data[0];
            int next = 1;
            int bitsLeft = 8;
            
            while (count < bufSize && (bitsLeft > 0 || next < length))
            {
                if (bitsLeft < 5)
                {
                    if (next < length)
                    {
                        buffer <<= 8;
                        buffer |= data[next++] & 0xFF;
                        bitsLeft += 8;
                    }
                    else
                    {
                        int pad = 5 - bitsLeft;
                        buffer <<= pad;
                        bitsLeft += pad;
                    }
                }

                int index = 0x1F & (buffer >> (bitsLeft - 5));
                bitsLeft -= 5;
                result[count++] = "abcdefghijklmnopqrstuvwxyz234567"[index];

                if ((count - flagCount) % 60 == 0)
                {
                    flagCount++;
                    lastFlag = count;
                    result[count++] = 60;
                }
            }
        }

        if (lastFlag != -1)
        {
            result[lastFlag] = count - lastFlag - 1;
        }

        if (count < bufSize)
        {
            result[count] = '\000';
        }

        return count;
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
        this->header.answer_rrs = this->server && this->fragment ? htons(0x0001) : 0;

        if (this->fragment)
        {
            char processed[MTU_SIZE * 2];
            int blen = base32_encode((const unsigned char*)message + *offset, length, (unsigned char*)&processed, sizeof(processed));
            memcpy(message + *offset, &processed, blen);
            length = blen;
            this->header.length = (unsigned char)min(length, 60);
        }

        if (this->domain_len != 0)
        {
            length = _encapsulate(message, length, offset, nullptr, 0, this->domain, this->domain_len);
        }

        return _encapsulate(message, length, offset, (char*)&this->header, sizeof(this->header), this->server && this->fragment ? (char*)&this->answer_footer : (char*)&this->footer, this->server && this->fragment ? sizeof(this->answer_footer) : sizeof(this->footer));
    }

    virtual int decapsulate(char* message, int length, int* offset)
    {
        if (this->server)
        {
            this->header.transaction_id = ((unsigned short*)(message + *offset))[0];
        }

        length = _decapsulate(message, length, offset, sizeof(this->header), !this->server && this->fragment ? sizeof(this->answer_footer) : sizeof(this->footer));

        if (this->domain_len != 0)
        {
            length = _decapsulate(message, length, offset, 0, this->domain_len);
            *(message + *offset + length) = 0;
        }

        if (this->fragment)
        {
            char processed[MTU_SIZE * 2];
            int blen = base32_decode((const unsigned char*)message + *offset, (unsigned char*)&processed, sizeof(processed));

            if (blen < 1)
            {
                hexdump(message + *offset, length);
                fprintf(stderr, "Failed to decode base32-encoded DNS payload.\n");
                return blen;
            }

            memcpy(message + *offset, &processed, blen);
            length = blen;
        }

        return length;
    }
};
