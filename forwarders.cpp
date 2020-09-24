#pragma once
#include "shared.cpp"
#include "transport_base.cpp"
#include "obfuscate_base.cpp"
#include "mocker_base.cpp"

int loop_transports_select(transport_base *local, transport_base *remote, obfuscate_base *obfuscator, mocker_base *mocker)
{
    struct pollfd fds[2];
    memset(fds, 0 , sizeof(fds));

    if (!local->started)
    {
        if (local->start() != EXIT_SUCCESS)
        {
            return EXIT_FAILURE;
        }
    }
    if (!remote->started)
    {
        if (remote->start() != EXIT_SUCCESS)
        {
            return EXIT_FAILURE;
        }
    }

    if (mocker != nullptr)
    {
        if (mocker->setup(local, remote) != EXIT_SUCCESS)
        {
            return EXIT_FAILURE;
        }

        if (mocker->can_handshake)
        {
            if (mocker->handshake(local, remote) != EXIT_SUCCESS)
            {
                return EXIT_FAILURE;
            }
        }
    }

    fds[0].fd = local->get_selectable();
    fds[0].events = POLLIN;
    fds[1].fd = remote->get_selectable();
    fds[1].events = POLLIN;

    int msglen, offset;
    char buffer[MTU_SIZE * 3];
    bool restart[2] = { false, false };
    while (run)
    {
        msglen = poll(fds, 2, 3 * 60 * 1000);

        if ((fds[0].revents & (POLLHUP | POLLERR | POLLNVAL)) != 0 || restart[0])
        {
            sleep(1);
            local->restart();
            restart[0] = false;
            fds[0].fd = local->get_selectable();

            if (mocker != nullptr && mocker->can_handshake && mocker->server)
            {
                if (mocker->handshake(local, remote) != EXIT_SUCCESS)
                {
                    restart[0] = true;
                    continue;
                }
            }
        }

        if ((fds[1].revents & (POLLHUP | POLLERR | POLLNVAL)) != 0 || restart[1])
        {
            sleep(1);
            remote->restart();
            restart[1] = false;
            fds[1].fd = local->get_selectable();

            if (mocker != nullptr && mocker->can_handshake && !mocker->server)
            {
                if (mocker->handshake(local, remote) != EXIT_SUCCESS)
                {
                    restart[1] = true;
                    continue;
                }
            }
        }

        if (fds[0].revents == POLLIN)
        {
            msglen = local->receive(buffer + MTU_SIZE, &offset);

            if (msglen < 1)
            {
                goto next_fd;
            }

            if (mocker != nullptr && mocker->can_encapsulate && mocker->server)
            {
                msglen = mocker->decapsulate(buffer + MTU_SIZE, msglen, &offset);

                if (msglen < 1)
                {
                    goto next_fd;
                }
            }

            if (obfuscator != nullptr)
            {
                msglen = obfuscator->encipher(buffer + MTU_SIZE + offset, msglen);

                if (msglen < 1)
                {
                    goto next_fd;
                }
            }

            if (mocker != nullptr && mocker->can_encapsulate && !mocker->server)
            {
                msglen = mocker->encapsulate(buffer + MTU_SIZE, msglen, &offset);

                if (msglen < 1)
                {
                    goto next_fd;
                }
            }

            remote->send(buffer + MTU_SIZE + offset, msglen);
        }

    next_fd:
        if (fds[1].revents == POLLIN)
        {
            msglen = remote->receive(buffer + MTU_SIZE, &offset);

            if (msglen < 1)
            {
                continue;
            }

            if (mocker != nullptr && mocker->can_encapsulate && !mocker->server)
            {
                msglen = mocker->decapsulate(buffer + MTU_SIZE, msglen, &offset);

                if (msglen < 1)
                {
                    continue;
                }
            }

            if (obfuscator != nullptr)
            {
                msglen = obfuscator->decipher(buffer + MTU_SIZE + offset, msglen);

                if (msglen < 1)
                {
                    continue;
                }
            }

            if (mocker != nullptr && mocker->can_encapsulate && mocker->server)
            {
                msglen = mocker->encapsulate(buffer + MTU_SIZE, msglen, &offset);

                if (msglen < 1)
                {
                    continue;
                }
            }

            local->send(buffer + MTU_SIZE + offset, msglen);
        }
    }

    local->stop();
    remote->stop();

    return run ? EXIT_FAILURE : EXIT_SUCCESS;
}

volatile bool block_local, block_remote;

int loop_transports_thread(transport_base *local, transport_base *remote, obfuscate_base *obfuscator, mocker_base *mocker)
{
    std::thread threads[2];

    if (!local->started)
    {
        if (local->start() != EXIT_SUCCESS)
        {
            return EXIT_FAILURE;
        }
    }
    if (!remote->started)
    {
        if (remote->start() != EXIT_SUCCESS)
        {
            return EXIT_FAILURE;
        }
    }

    if (mocker != nullptr)
    {
        if (mocker->setup(local, remote) != EXIT_SUCCESS)
        {
            return EXIT_FAILURE;
        }

        if (mocker->can_handshake)
        {
            if (mocker->handshake(local, remote) != EXIT_SUCCESS)
            {
                return EXIT_FAILURE;
            }
        }
    }

    threads[0] = std::thread([](transport_base *local, transport_base *remote, obfuscate_base *obfuscator, mocker_base *mocker)
    {
        int msglen, offset;
        char buffer[MTU_SIZE * 3];
        bool restart = false;
        while (run)
        {
            while (block_local)
            {
                sleep(1);
            }

            msglen = local->receive(buffer + MTU_SIZE, &offset);

            if (msglen < 1 || restart)
            {
                block_remote = true;

                sleep(1);
                local->restart();
                restart = false;

                if (mocker != nullptr && mocker->can_handshake && mocker->server)
                {
                    if (mocker->handshake(local, remote) != EXIT_SUCCESS)
                    {
                        restart = true;
                        continue;
                    }
                }

                block_remote = false;
                continue;
            }

            if (mocker != nullptr && mocker->can_encapsulate && mocker->server)
            {
                msglen = mocker->decapsulate(buffer + MTU_SIZE, msglen, &offset);

                if (msglen < 1)
                {
                    continue;
                }
            }

            if (obfuscator != nullptr)
            {
                msglen = obfuscator->encipher(buffer + MTU_SIZE + offset, msglen);

                if (msglen < 1)
                {
                    continue;
                }
            }

            if (mocker != nullptr && mocker->can_encapsulate && !mocker->server)
            {
                msglen = mocker->encapsulate(buffer + MTU_SIZE, msglen, &offset);

                if (msglen < 1)
                {
                    continue;
                }
            }

            remote->send(buffer + MTU_SIZE + offset, msglen);
        }
    }, std::cref(local), std::cref(remote), std::cref(obfuscator), std::cref(mocker));

    threads[1] = std::thread([](transport_base *local, transport_base *remote, obfuscate_base *obfuscator, mocker_base *mocker)
    {
        int msglen, offset;
        char buffer[MTU_SIZE * 3];
        bool restart = false;
        while (run)
        {
            while (block_remote)
            {
                sleep(1);
            }

            msglen = remote->receive(buffer + MTU_SIZE, &offset);

            if (msglen < 1 || restart)
            {
                block_local = true;

                sleep(1);
                remote->restart();
                restart = false;

                if (mocker != nullptr && mocker->can_handshake && !mocker->server)
                {
                    if (mocker->handshake(local, remote) != EXIT_SUCCESS)
                    {
                        restart = true;
                        continue;
                    }
                }

                block_local = false;
                continue;
            }

            if (mocker != nullptr && mocker->can_encapsulate && !mocker->server)
            {
                msglen = mocker->decapsulate(buffer + MTU_SIZE, msglen, &offset);

                if (msglen < 1)
                {
                    continue;
                }
            }

            if (obfuscator != nullptr)
            {
                msglen = obfuscator->decipher(buffer + MTU_SIZE + offset, msglen);

                if (msglen < 1)
                {
                    continue;
                }
            }

            if (mocker != nullptr && mocker->can_encapsulate && mocker->server)
            {
                msglen = mocker->encapsulate(buffer + MTU_SIZE, msglen, &offset);

                if (msglen < 1)
                {
                    continue;
                }
            }

            local->send(buffer + MTU_SIZE + offset, msglen);
        }
    }, std::cref(local), std::cref(remote), std::cref(obfuscator), std::cref(mocker));

    for (int i = 0; i < 2; i++)
    {
        threads[i].join();  
    }

    local->stop();
    remote->stop();

    return run ? EXIT_FAILURE : EXIT_SUCCESS;
}
