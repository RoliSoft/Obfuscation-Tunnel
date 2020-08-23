#include "shared.c"
#include "udp_udp_tunnel.c"
#include "udp_tcp_tunnel.c"
#include "tcp_udp_tunnel.c"
#include "udp_icmp_tunnel.c"
#include "icmp_udp_tunnel.c"

int main(int argc, char* argv[])
{
    signal(SIGINT, sig_handler);

    struct session s;

    int ret = parse_arguments(argc, argv, &s);
    if (ret == EXIT_SUCCESS || ret == EXIT_FAILURE)
    {
        return ret;
    }

    switch (s.mode)
    {
        default:
        case MODE_UDP_UDP:
            return udp_udp_tunnel(&s);

        case MODE_UDP_TCP:
            return udp_tcp_tunnel(&s);

        case MODE_TCP_UDP:
            return tcp_udp_tunnel(&s);

        case MODE_UDP_ICMP:
            return udp_icmp_tunnel(&s);

        case MODE_ICMP_UDP:
            return icmp_udp_tunnel(&s);
    }
}
