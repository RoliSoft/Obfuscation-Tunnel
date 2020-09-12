#pragma once
#include "shared.cpp"

class obfuscate_base
{
public:
    virtual int encipher(char* message, int length) = 0;
    virtual int decipher(char* message, int length) = 0;
};
