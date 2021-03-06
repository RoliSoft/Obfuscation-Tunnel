#pragma once
#include "shared.cpp"
#include "transport_base.cpp"

class icmp6_base : virtual public transport_base
{
public:
    bool random_id = false;
    int sequence = 0;
    int identifier = 0;

protected:
    inline int _send(int fd, bool reply, const struct sockaddr_in6 *addr, char *buffer, ssize_t msglen)
    {
        *((unsigned short*)&buffer[-ICMP_LEN]) = reply ? 0x81 : 0x80; // type -> echo reply or request
        *((unsigned short*)&buffer[-ICMP_LEN + 4]) = reply && this->random_id ? htons(this->identifier) : 0x3713; // identifier
        *((unsigned short*)&buffer[-ICMP_LEN + 6]) = htons(this->sequence); // sequence
        *((unsigned short*)&buffer[-ICMP_LEN + 2]) = 0; // zero checksum before calculation
        *((unsigned short*)&buffer[-ICMP_LEN + 2]) = ip_checksum(&buffer[-ICMP_LEN], msglen + ICMP_LEN);

        if (!reply) ++this->sequence;

        int res = sendto(fd, buffer - ICMP_LEN, msglen + ICMP_LEN, 0, (const struct sockaddr*)addr, IP6_SIZE);

        if (res < 0)
        {
            perror("Failed to send ICMPv6 packet");
        }

        return res;
    }

    inline int _receive(int fd, bool reply, struct sockaddr_in6 *addr, char *buffer, int* offset)
    {
#ifndef AF_PACKET
        struct sockaddr_in6 temp_addr;
#endif

        socklen_t addrlen = IP6_SIZE;
        ssize_t msglen = recvfrom(fd, buffer, MTU_SIZE, 0, 
#ifdef AF_PACKET
                (struct sockaddr*)addr
#else
                (struct sockaddr*)&temp_addr
#endif
                , &addrlen);

        if (msglen == -1)
        {
            if (run && errno != ETIMEDOUT)
            {
                perror("Failed to read ICMPv6 packet");
            }

            return msglen;
        }

#ifndef AF_PACKET
        if ((unsigned char)buffer[0] != (reply ? 0x80 : 0x81) || (!this->random_id && ((unsigned char)buffer[4] != 0x13 || (unsigned char)buffer[5] != 0x37)))
        {
            return 0;
        }

        // make sure the return address is not overwritten if not tunnel packet
        *(struct sockaddr_in6*)addr = temp_addr;
#endif

        if (this->verbose) printf("Received %zd bytes from remote\n", msglen - ICMP6_SKIP);

        if (reply)
        {
            if (this->random_id) this->identifier = ntohs(*((unsigned short*)&buffer[ICMP_ID_OFFSET]));
            this->sequence = ntohs(*((unsigned short*)&buffer[ICMP_SEQ_OFFSET]));
        }

        *offset = ICMP6_SKIP;
        return msglen - ICMP6_SKIP;
    }

#if HAVE_PCAP
    inline int _receive_pcap(pcap_t *ptr, bool reply, struct sockaddr_in6 *addr, char *buffer, int* offset)
    {
        const u_char *cap_buffer;
        struct pcap_pkthdr *cap_data;
        int res = pcap_next_ex(ptr, &cap_data, &cap_buffer);

        if (res < 1)
        {
            if (run && res < 0)
            {
                pcap_perror(ptr, "Failed to read ICMPv6 packet with PCAP");
            }

            return res;
        }

        if (reply)
        {
            if (!this->connected)
            {
                memset(addr, 0, sizeof(*addr));
                addr->sin6_family = AF_INET6;
                addr->sin6_addr = *((struct in6_addr*)(cap_buffer + ETHHDR_LEN + IP6HDR_SRC_OFFSET));
            }

            addr->sin6_addr = *((struct in6_addr*)(cap_buffer + ETHHDR_LEN + IP6HDR_SRC_OFFSET));

            if (this->random_id) this->identifier = ntohs(*((unsigned short*)&cap_buffer[ETHHDR_LEN + IP6HDR_LEN + ICMP_ID_OFFSET]));
            this->sequence = ntohs(*((unsigned short*)&cap_buffer[ETHHDR_LEN + IP6HDR_LEN + ICMP_SEQ_OFFSET]));
        }

        memcpy(buffer, cap_buffer + PCAP_ICMP6_SKIP, cap_data->caplen - PCAP_ICMP6_SKIP);

        *offset = 0;
        return cap_data->caplen - PCAP_ICMP6_SKIP;
    }
#endif

protected:
    icmp6_base(bool random_id = false)
        : random_id(random_id)
    {
    }
};
