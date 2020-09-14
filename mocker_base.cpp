#pragma once
#include "shared.cpp"

#define MOCK_LOCAL 0
#define MOCK_REMOTE 1

class mocker_base
{
public:
    bool server;

    virtual int setup(transport_base *local, transport_base *remote)
    {
        (void)local;
        (void)remote;
        return EXIT_SUCCESS;
    }

    virtual int encapsulate(char* message, int length, int* offset)
    {
        (void)message;
        *offset = 0;
        return length;
    }
    
    virtual int decapsulate(char* message, int length, int* offset)
    {
        (void)message;
        *offset = 0;
        return length;
    }

protected:
    mocker_base(bool server)
        : server(server)
    {
    }

    static inline int _encapsulate(char* message, int length, int* offset, char* header, int header_len, char* footer, int footer_len)
    {
        if (footer_len != 0)
        {
            memcpy(message + *offset + length, footer, footer_len);
        }

        if (header_len != 0)
        {
            *offset -= header_len;
            memcpy(message + *offset, header, header_len);
        }

        return length + header_len + footer_len;
    }

    static inline int _decapsulate(char* message, int length, int* offset, int header_len, int footer_len)
    {
        (void)message;
        *offset += header_len;
        return length - header_len - footer_len;
    }
};
