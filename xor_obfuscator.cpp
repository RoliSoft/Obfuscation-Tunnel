#pragma once
#include "shared.cpp"
#include "obfuscate_base.cpp"

class xor_obfuscator : virtual public obfuscate_base
{
public:
    char* key;
    int key_length;

    xor_obfuscator(char *key, int key_length)
        : key(key), key_length(key_length)
    {
        if (key == nullptr || key[0] == 0)
        {
            this->key = (char*)"X5O!P%@AP[""4\\PZX54(P^"")7CC)7}$EI""CAR-STANDA""RD-ANTIVIR""US-TEST-FI""LE!$H+H*"; // :)
            this->key_length = strlen(this->key);

            printf("Obfuscating packets with XOR and built-in key.\n");
        }
        else
        {
            printf("Obfuscating packets with XOR and %d-byte key.\n", this->key_length);
        }
    }

    xor_obfuscator(struct session* session)
        : xor_obfuscator(session->key, session->key_length)
    {
    }

    static inline int process(char* message, int length, char* key, int key_length)
    {
        for (int i = 0; i < length; i++)
        {
            message[i] ^= key[i % key_length];
        }
        
        return length;
    }

    virtual int encipher(char* message, int length)
    {
        return process(message, length, this->key, this->key_length);
    }

    virtual int decipher(char* message, int length)
    {
        return process(message, length, this->key, this->key_length);
    }
};
