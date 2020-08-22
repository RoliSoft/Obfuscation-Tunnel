#include "shared.c"
#include "udp_udp_tunnel.c"
#include "udp_tcp_tunnel.c"
#include "tcp_udp_tunnel.c"

int main(int argc, char* argv[])
{
    signal(SIGINT, sig_handler);

    int mode = MODE_UDP_UDP, verbose = 0, obfuscate = 0, res;
    struct sockaddr_in localaddr, remoteaddr;
    int localport = 8080, remoteport = 0;

    int ret = parse_arguments(argc, argv, &mode, &verbose, &obfuscate, &localaddr, &localport, &remoteaddr, &remoteport);
    if (ret == EXIT_SUCCESS || ret == EXIT_FAILURE)
    {
        return ret;
    }

    switch (mode)
    {
        default:
        case MODE_UDP_UDP:
            return udp_udp_tunnel(verbose, obfuscate, localaddr, localport, remoteaddr, remoteport);

        case MODE_UDP_TCP:
            return udp_tcp_tunnel(verbose, obfuscate, localaddr, localport, remoteaddr, remoteport);

        case MODE_TCP_UDP:
            return tcp_udp_tunnel(verbose, obfuscate, localaddr, localport, remoteaddr, remoteport);
    }
}
