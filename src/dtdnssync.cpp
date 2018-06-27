#include "dtdnssync.hpp"

#include <iostream>

using namespace dtdnssync;

int main(int argc, char ** argv)
{
    std::string cfg_path{ "/etc/dtdnssync/dtdnssync.cfg" };
    int argc_progress = 1;

    if (argc < 2) {
        std::cerr << "No command given! Try " << argv[0] << " help\n";
        return EXIT_FAILURE;
    }

    if (::strcmp(argv[argc_progress], "--cfg") == 0) {
        if (!argv[++argc_progress]) {
            std::cerr << "Option --cfg need an argument!\n";
            return EXIT_FAILURE;
        }
        cfg_path = argv[argc_progress];
        ++argc_progress;

        if (argc < 4) {
            std::cerr << "No command given! Try " << argv[0] << " help\n";
            return EXIT_FAILURE;
        } else if (argc > 4) {
            std::cerr << "Invalid command given! Try " << argv[0] << " help\n";
            return EXIT_FAILURE;
        }
    }

    if (::strcmp(argv[argc_progress], "help") == 0 or ::strcmp(argv[argc_progress], "-h") == 0 or ::strcmp(argv[1], "--help") == 0) {
        std::cout << "dtdnssync " << version << "\n"
                  << "usage: " << argv[0] << " [options] command\n"
                  << "\n"
                  << "  options:\n"
                  << "    --cfg PATH       use custom configuration file (default: " << cfg_path << ")\n"
                  << "\n"
                  << "  commands:\n"
                  << "    currentip        get IP currently set for your domain\n"
                  << "    externip         get your current external IP\n"
                  << "    update           update the IP for your domain\n"
                  << "    check            check if an update is needed\n"
                  << "    dumpconfig       show configuration\n"
                  << "    version          show version\n"
                  << "    help             this help overview\n"
                  << "\n";
        return EXIT_SUCCESS;
    }

    if (::strcmp(argv[argc_progress], "version") == 0 or ::strcmp(argv[argc_progress], "--version") == 0) {
        std::cout << version << '\n';
        return EXIT_SUCCESS;
    }

    dtdnssync_config cfg;

    try {
        cfg = parse_config(cfg_path);
    } catch (const std::exception & e) {
        std::cerr << "Can not parse config file '" + cfg_path + "': " << e.what() << '\n';
        return EXIT_FAILURE;
    }

    if (::strcmp(argv[argc_progress], "currentip") == 0) {
        try {
            asio::io_service io_service;
            std::vector<asio::ip::address> addresses = task_ip(io_service, cfg.hostname);
            std::cout << "address(es) for " << cfg.hostname << ":";
            for (const asio::ip::address & addr : addresses) {
                std::cout << " " << addr;
            }
            std::cout << "\n";

        } catch (const std::exception & e) {
            std::cerr << "Unable to get IP address for " << cfg.hostname << ": " << e.what() << '\n';
            return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
    } else if (::strcmp(argv[argc_progress], "externip") == 0) {
        try {
            asio::io_service io_service;
            auto ssl_ctx = setup_ssl_context(cfg.cert_file);
            auto ip = task_externip(io_service, ssl_ctx);
            std::cout << "current external ip: " << ip << "\n";

        } catch (const std::exception & e) {
            std::cerr << "Unable to get external IP address: " << e.what() << '\n';
            return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
    } else if (::strcmp(argv[argc_progress], "dumpconfig") == 0) {
        std::cout << "configuration from file " + cfg_path + ":\n"
                  << "  interval          : " << cfg.interval << '\n'
                  << "  cert_file         : " << cfg.cert_file << '\n'
                  << "  debug             : " << std::boolalpha << cfg.debug << '\n'
                  << "  hostname          : " << cfg.hostname << '\n'
                  << "  password          : ********\n"
                  << '\n';

        return EXIT_SUCCESS;
    } else if (::strcmp(argv[argc_progress], "update") == 0) {
        try {
            asio::io_service io_service;
            auto ssl_ctx = setup_ssl_context(cfg.cert_file);
            task_updateip(io_service, cfg.hostname, cfg.password, ssl_ctx);
        } catch (const std::exception & e) {
            std::cerr << "Unable to update IP: " << e.what() << '\n';
            return EXIT_FAILURE;
        }

        std::cout << "IP address for " << cfg.hostname << " was successfully updated\n";

        return EXIT_SUCCESS;
    } else if (::strcmp(argv[argc_progress], "check") == 0) {
        try {
            asio::io_service io_service;
            auto ssl_ctx = setup_ssl_context(cfg.cert_file);
            auto externip = task_externip(io_service, ssl_ctx);
            auto ips = task_ip(io_service, cfg.hostname);
            bool match{ false };

            for (const auto & ip : ips) {
                if (ip == externip) {
                    match = true;
                    break;
                }
            }

            if (match) {
                std::cout << "IP is up to date for " << cfg.hostname << " (" << externip << ")\n";
            } else {
                std::cout << "IP is out of date for " << cfg.hostname << " (dns: ";
                for (const auto & ip : ips) {
                    std::cout << ip << " ";
                }
                std::cout << " current: " << externip << ")\n";
            }

        } catch (const std::exception & e) {
            std::cerr << "Unable to check for IP update: " << e.what() << '\n';
            return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
    } else {
        std::cerr << "Invalid option '" << argv[argc_progress] << "'! Try " << argv[0] << " help\n";
        return EXIT_FAILURE;
    }
}
