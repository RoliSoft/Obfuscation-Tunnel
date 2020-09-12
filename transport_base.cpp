#pragma once
#include "shared.cpp"

class transport_base
{
public:
    bool started = false;
    bool connected = false;
    bool verbose;

    virtual int start() = 0;
    virtual int stop() = 0;
    virtual int send(char *buffer, ssize_t msglen) = 0;
    virtual int receive(char *buffer, int* offset) = 0;
    virtual int get_selectable() { return -1; }
    virtual int restart() { return -1; }

protected:
    transport_base(bool verbose = false)
        : verbose(verbose)
    {
    }
};
