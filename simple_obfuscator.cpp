#pragma once
#include "shared.cpp"
#include "obfuscate_base.cpp"

class simple_obfuscator : virtual public obfuscate_base
{
public:
    char key;

    simple_obfuscator(char *key)
    {
        if (key == nullptr || key[0] == 0)
        {
            this->key = 0x90; // nop sled anyone?

            printf("Obfuscating packets with simple obfuscator and built-in key.\n");
        }
        else
        {
            this->key = key[0];

            printf("Obfuscating packets with simple obfuscator and specified byte.\n");
        }
    }

    simple_obfuscator(struct session* session)
        : simple_obfuscator(session->key)
    {
    }

    static inline int process(char* message, int length, char key)
    {
        int process = min(16, length);

        if (length > 32)
        {
            for (int i = 0; i < process; i++)
            {
                message[i] ^= key ^ message[i + 16];
            }
        }
        else
        {
            for (int i = 0; i < process; i++)
            {
                message[i] ^= key;
            }
        }
        
        return length;
    }

    virtual int encipher(char* message, int length)
    {
        return process(message, length, this->key);
    }

    virtual int decipher(char* message, int length)
    {
        return process(message, length, this->key);
    }
};
