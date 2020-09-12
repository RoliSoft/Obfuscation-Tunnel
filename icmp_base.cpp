#pragma once
#include "shared.cpp"
#include "transport_base.cpp"

class icmp_base : virtual public transport_base
{
public:
    bool random_id = false;
    int sequence = 0;
    int identifier = 0;

protected:
    inline int _send(int fd, bool reply, const struct sockaddr *addr, char *buffer, ssize_t msglen)
    {
        *((unsigned short*)&buffer[-ICMP_LEN]) = reply ? 0x00 : 0x08; // type -> echo reply or request
        *((unsigned short*)&buffer[-ICMP_LEN + 4]) = reply && this->random_id ? htons(this->identifier) : 0x3713; // identifier
        *((unsigned short*)&buffer[-ICMP_LEN + 6]) = reply ? htons(this->sequence) : htons(this->sequence++); // sequence
        *((unsigned short*)&buffer[-ICMP_LEN + 2]) = 0; // zero checksum before calculation
        *((unsigned short*)&buffer[-ICMP_LEN + 2]) = ip_checksum(&buffer[-ICMP_LEN], msglen + ICMP_LEN);

        int res = sendto(fd, buffer - ICMP_LEN, msglen + ICMP_LEN, 0, addr, IP_SIZE);

        if (res < 0)
        {
            perror("Failed to send ICMP packet");
        }

        return res;
    }

    inline int _receive(int fd, bool reply, struct sockaddr *addr, char *buffer, int* offset)
    {
#ifndef AF_PACKET
        struct sockaddr_in temp_addr;
#endif

        socklen_t addrlen = IP_SIZE;
        ssize_t msglen = recvfrom(fd, buffer, MTU_SIZE, 0, 
#ifdef AF_PACKET
                addr
#else
                (struct sockaddr*)&temp_addr
#endif
                , &addrlen);

        if (msglen == -1)
        {
            if (run && errno != ETIMEDOUT)
            {
                perror("Failed to read ICMP packet");
            }

            return msglen;
        }

#ifndef AF_PACKET
        if ((unsigned char)buffer[IPHDR_LEN] != (reply ? 0x08 : 0x00) || (!this->random_id && ((unsigned char)buffer[4 + IPHDR_LEN] != 0x13 || (unsigned char)buffer[5 + IPHDR_LEN] != 0x37)))
        {
            return 0;
        }

        // make sure the return address is not overwritten if not tunnel packet
        *(struct sockaddr_in*)addr = temp_addr;
#endif

        if (this->verbose) printf("Received %zd bytes from remote\n", msglen - ICMP_SKIP);

        if (reply)
        {
            if (this->random_id) this->identifier = ntohs(*((unsigned short*)&buffer[IPHDR_LEN + ICMP_ID_OFFSET]));
            this->sequence = ntohs(*((unsigned short*)&buffer[IPHDR_LEN + ICMP_SEQ_OFFSET]));
        }

        *offset = ICMP_SKIP;
        return msglen - ICMP_SKIP;
    }

#if HAVE_PCAP
    inline int _receive_pcap(pcap_t *ptr, bool reply, struct sockaddr_in *addr, char *buffer, int* offset)
    {
        const u_char *cap_buffer;
        struct pcap_pkthdr *cap_data;
        int res = pcap_next_ex(ptr, &cap_data, &cap_buffer);

        if (res < 1)
        {
            if (run && res < 0)
            {
                pcap_perror(ptr, "Failed to read ICMP packet with PCAP");
            }

            return res;
        }

        if (reply)
        {
            if (!this->connected)
            {
                memset(addr, 0, sizeof(*addr));
                addr->sin_family = AF_INET;
            }

            addr->sin_addr = *((struct in_addr*)((char*)cap_buffer + ETHHDR_LEN + IPHDR_SRC_OFFSET));

            if (this->random_id) this->identifier = ntohs(*((unsigned short*)&cap_buffer[ETHHDR_LEN + IPHDR_LEN + ICMP_ID_OFFSET]));
            this->sequence = ntohs(*((unsigned short*)&cap_buffer[ETHHDR_LEN + IPHDR_LEN + ICMP_SEQ_OFFSET]));
        }

        memcpy(buffer, cap_buffer + PCAP_ICMP_SKIP, cap_data->caplen - PCAP_ICMP_SKIP);

        *offset = 0;
        return cap_data->caplen - PCAP_ICMP_SKIP;
    }
#endif

    icmp_base(bool random_id = false)
        : random_id(random_id)
    {
    }
};
