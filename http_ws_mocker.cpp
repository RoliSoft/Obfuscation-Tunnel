#pragma once
#include "shared.cpp"
#include "mocker_base.cpp"
#include "tcp_server.cpp"
#include "tcp_client.cpp"

class http_ws_mocker : virtual public mocker_base
{
protected:
    char *http_request = (char*)"GET /updates HTTP/1.1\r\nHost: docs.microsoft.com\r\nCache-Control: no-cache\r\nPragma: no-cache\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: 1LneJrQSPAs/QqaqblMEew==\r\nOrigin: http://docs.microsoft.com\r\n\r\n";
    char *http_response = (char*)"HTTP/1.1 101 Switching Protocols\r\nServer: Microsoft-IIS/10.0\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: MXvVhX119hHqUOkRYz4Tp0L4T4c=\r\n\r\n";
    char *http_request_check = (char*)"GET /updates HTTP/1.1\r";
    char *http_response_check = (char*)"HTTP/1.1 101 Switching Protocols\r";
    char *http_response_404 = (char*)"HTTP/1.1 404 Not Found\r\nServer: Microsoft-IIS/10.0\r\n\r\n";

public:
    http_ws_mocker(bool server)
        : mocker_base(server, true, false)
    {
        printf("Masquerading packets into HTTP WebSocket stream.\n");
    }

    http_ws_mocker(struct session* session)
        : http_ws_mocker(strcmp(session->mocker, "http_ws_server") == 0)
    {
    }

    virtual int setup(transport_base *local, transport_base *remote)
    {
        if (this->server)
        {
            tcp_server* tcp = dynamic_cast<tcp_server*>(local);
            if (tcp == nullptr)
            {
                fprintf(stderr, "The http_ws_server module requires TCP local to function.\n");
                return EXIT_FAILURE;
            }
        }
        else
        {
            tcp_client* tcp = dynamic_cast<tcp_client*>(remote);
            if (tcp == nullptr)
            {
                fprintf(stderr, "The http_ws_client module requires TCP remote to function.\n");
                return EXIT_FAILURE;
            }

            return EXIT_SUCCESS;
        }

        return EXIT_SUCCESS;
    }

    virtual int handshake(transport_base *local, transport_base *remote)
    {
        int length, offset;
        char buffer[MTU_SIZE];

        if (this->server)
        {
            printf("Performing HTTP WebSocket handshake...\n");

            tcp_server* tcp = dynamic_cast<tcp_server*>(local);
            int original_encoding = tcp->encoding;
            tcp->encoding = LENGTH_NONE;

            length = tcp->receive((char*)&buffer, &offset);

            if (length == 0)
            {
                fprintf(stderr, "Connection interrupted during handshake.\n");
                tcp->disconnect();
                tcp->encoding = original_encoding;
                return EXIT_FAILURE;
            }

            char* token = strtok(buffer, "\n");
            if (strcmp(token, this->http_request_check) != 0)
            {
                fprintf(stderr, "Received invalid request from client: %s\n", token);

                tcp->send(this->http_response_404, strlen(this->http_response_404));
                tcp->disconnect();

                tcp->encoding = original_encoding;
                return EXIT_FAILURE;
            }

            length = tcp->send(this->http_response, strlen(this->http_response));

            if (length == 0)
            {
                fprintf(stderr, "Connection interrupted during handshake.\n");
                tcp->disconnect();
                tcp->encoding = original_encoding;
                return EXIT_FAILURE;
            }

            printf("HTTP upgraded to WebSocket stream.\n");
            tcp->encoding = original_encoding;
        }
        else
        {
            printf("Performing HTTP WebSocket handshake...\n");

            tcp_client* tcp = dynamic_cast<tcp_client*>(remote);
            int original_encoding = tcp->encoding;
            tcp->encoding = LENGTH_NONE;

            length = tcp->send(this->http_request, strlen(this->http_request));

            if (length == 0)
            {
                fprintf(stderr, "Connection interrupted during handshake.\n");
                tcp->stop();
                tcp->encoding = original_encoding;
                return EXIT_FAILURE;
            }

            length = tcp->receive((char*)&buffer, &offset);

            if (length == 0)
            {
                fprintf(stderr, "Connection interrupted during handshake.\n");
                tcp->stop();
                tcp->encoding = original_encoding;
                return EXIT_FAILURE;
            }

            char* token = strtok(buffer, "\n");
            if (strcmp(token, this->http_response_check) != 0)
            {
                fprintf(stderr, "Received invalid response from server: %s\n", token);
                tcp->stop();
                tcp->encoding = original_encoding;
                return EXIT_FAILURE;
            }

            printf("HTTP upgraded to WebSocket stream.\n");
            tcp->encoding = original_encoding;
        }

        return EXIT_SUCCESS;
    }
};
