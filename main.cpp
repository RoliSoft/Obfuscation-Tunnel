#include "factory.cpp"

int main(int argc, char* argv[])
{
    signal(SIGINT, sig_handler);

    struct session session;

    int ret = parse_arguments(argc, argv, &session);
    if (ret == EXIT_SUCCESS || ret == EXIT_FAILURE)
    {
        return ret;
    }

    return run_session(&session);
}
