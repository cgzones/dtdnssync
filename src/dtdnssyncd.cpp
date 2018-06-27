#include "dtdnssync.hpp"

#include "logger.hpp"

#include <getopt.h>
#include <grp.h>
#include <iostream>
#include <pwd.h>
#include <signal.h>
#include <sys/types.h>

using namespace dtdnssync;

static void daemonize();
static void daemon(const dtdnssync_config & cfg);
static void signal_handler(int sig);

static volatile bool running = true;
static volatile bool restart = false;

int main(int argc, char ** argv)
{
    std::string cfg_path{ "/etc/dtdnssync/dtdnssync.cfg" };
    std::string log_path{ "/var/log/dtdnssyncd.log" };
    int debug_flag = 0;
    bool foreground = false;

    while (true) {
        const struct option long_options[] = { { "debug", no_argument, &debug_flag, 1 },
                                               { "cfg-file", required_argument, nullptr, 'c' },
                                               { "log-file", required_argument, nullptr, 'l' },
                                               { "foreground", no_argument, nullptr, 'f' },
                                               { "version", no_argument, nullptr, 'v' },
                                               { "help", no_argument, nullptr, 'h' },
                                               { nullptr, 0, nullptr, 0 } };
        int option_index = 0;

        const int c = getopt_long(argc, argv, "dc:hfvl:", long_options, &option_index);

        if (c == -1) {
            break;
        }

        switch (c) {
            case 0:
                if (long_options[option_index].flag != nullptr) {
                    break;
                }
                printf("option %s", long_options[option_index].name);
                if (optarg != nullptr) {
                    printf(" with arg %s", optarg);
                }
                printf("\n");
                break;

            case 'c':
                cfg_path = optarg;
                break;

            case 'l':
                log_path = optarg;
                break;

            case 'f':
                foreground = true;
                break;

            case 'h':
                std::cout << "dtdnssyncd " << version << '\n'
                          << "usage: " << argv[0] << " [options]\n"
                          << "\n"
                          << "  options:\n"
                          << "    -c --cfg-file PATH    use custom configuration file "
                             "(default: "
                          << cfg_path << ")\n"
                          << "    -l --log-file PATH    specify log file (default: " << log_path << ")\n"
                          << "    -f --foreground       run daemon in foreground\n"
                          << "    -d --debug            turn on debug output\n"
                          << "    -v --version          display version and exit\n"
                          << "    -h --help             this help overview\n"
                          << "\n";
                return EXIT_SUCCESS;

            case 'v':
                std::cout << version << '\n';
                return EXIT_SUCCESS;

            case '?':
                /* getopt_long already printed an error message. */
                std::cerr << "EXITING!!!\n";
                return EXIT_FAILURE;

            default:
                std::cerr << "EXITING!!!\n";
                return EXIT_FAILURE;
        }
    }

    if (optind < argc) {
        std::cerr << "non-option arguments: ";
        for (; optind < argc; ++optind) {
            std::cerr << argv[optind];
        }
        std::cerr << '\n';
        std::cerr << "EXITING!!!\n";
        return EXIT_FAILURE;
    }

    do {
        restart = false;
        running = true;

        dtdnssync_config cfg;

        try {
            cfg = parse_config(cfg_path);
        } catch (const std::exception & e) {
            std::cerr << "Can not parse config: " << e.what() << '\n';
            std::cerr << "EXITING!!!\n";
            return EXIT_FAILURE;
        }

        FILELog::domain() = "dtdnssyncd";
        if (debug_flag == 1 or cfg.debug) {
            FILELog::reporting_level() = log_level::DEBUG;
        } else {
            FILELog::reporting_level() = log_level::INFO;
        }
        if (foreground) {
            Output2FILE::stream() = ::stdout;
        } else if ((Output2FILE::stream() = ::fopen(log_path.c_str(), "a")) == nullptr) {
            std::cerr << "Can not open " << log_path << ": " << ::strerror(errno) << '\n';
            std::cerr << "EXITING!!!\n";
            return EXIT_FAILURE;
        }

        if (cfg.hostname.empty() or cfg.hostname == "yourdomain") {
            std::cerr << "Configuration: Hostname not set     Exiting\n";
            FILE_LOG(log_level::WARNING) << "Configuration: Hostname not set     Exiting\n";
            return EXIT_SUCCESS;
        }

        FILE_LOG(log_level::DEBUG) << "configuration:";
        FILE_LOG(log_level::DEBUG) << "  interval          : " << cfg.interval;
        FILE_LOG(log_level::DEBUG) << "  cert_file         : " << cfg.cert_file;
        FILE_LOG(log_level::DEBUG) << "  debug             : " << std::boolalpha << cfg.debug;
        FILE_LOG(log_level::DEBUG) << "  hostname          : " << cfg.hostname;
        FILE_LOG(log_level::DEBUG) << "  password          : " << (cfg.password.empty() ? "empty" : "********");

        daemonize();

        FILE_LOG(log_level::INFO) << "Starting for host '" << cfg.hostname << "' with an interval of " << cfg.interval << " minutes";

        try {
            daemon(cfg);
        } catch (const std::exception & e) {
            FILE_LOG(log_level::ERROR) << "Unhandled exception escaped: " << e.what();
            FILE_LOG(log_level::ERROR) << "EXITING!!!";
            return EXIT_FAILURE;
        } catch (...) {
            FILE_LOG(log_level::ERROR) << "Unknown exception escaped!";
            FILE_LOG(log_level::ERROR) << "EXITING!!!";
            return EXIT_FAILURE;
        }
    } while (restart);

    FILE_LOG(log_level::INFO) << "ending";

    return EXIT_SUCCESS;
}

static void signal_handler(int sig)
{
    switch (sig) {
        case SIGHUP:
            FILE_LOG(log_level::INFO) << "hangup signal caught - reloading";
            running = false;
            restart = true;
            break;
        case SIGINT:
            FILE_LOG(log_level::INFO) << "interrupt signal caught - stopping";
            running = false;
            break;
        case SIGTERM:
            FILE_LOG(log_level::ERROR) << "terminate signal caught";
            FILE_LOG(log_level::WARNING) << "Exiting!";
            exit(0);
    }
}

static void daemonize()
{
    ::signal(SIGCHLD, SIG_IGN);
    ::signal(SIGTSTP, SIG_IGN);
    ::signal(SIGTTOU, SIG_IGN);
    ::signal(SIGTTIN, SIG_IGN);
    ::signal(SIGINT, signal_handler);
    ::signal(SIGHUP, signal_handler);
    ::signal(SIGTERM, signal_handler);

    ::umask(027);

    if (::chdir("/") == -1) {
        FILE_LOG(log_level::ERROR) << "Can not chdir to /: " << ::strerror(errno);
        FILE_LOG(log_level::WARNING) << "Exiting!";
        exit(1);
    }

    if (::getuid() == 0) {
        FILE_LOG(log_level::WARNING) << "Running daemon as user root";
    } else if (::geteuid() == 0) {
        FILE_LOG(log_level::WARNING) << "Running daemon as effective user root";
    } else if (::getgid() == 0) {
        FILE_LOG(log_level::WARNING) << "Running daemon as group root";
    }
}

static void run(const dtdnssync_config & cfg, asio::ip::address & externip_cached, asio::ssl::context & ssl_ctx)
{
    FILE_LOG(log_level::DEBUG) << "running new check...";

    try {
        asio::io_service io_service;

        const auto externip = task_externip(io_service, ssl_ctx);
        FILE_LOG(log_level::DEBUG) << "current extern IP: " << externip;
        FILE_LOG(log_level::DEBUG) << "cached extern IP:  " << externip_cached;

        if (externip == externip_cached) {
            FILE_LOG(log_level::DEBUG) << "extern IP not changed, no need to update IP";
        } else {
            FILE_LOG(log_level::DEBUG) << "extern IP might have changed";

            const auto hostnameips = task_ip(io_service, cfg.hostname);
            FILE_LOG(log_level::DEBUG) << "hostname IPs: ";
            for (const auto & ip : hostnameips) {
                FILE_LOG(log_level::DEBUG) << "- " << ip;
            }

            bool uptodate = false;
            for (const auto & ip : hostnameips) {
                if (ip == externip) {
                    uptodate = true;
                    break;
                }
            }

            if (!uptodate) {
                FILE_LOG(log_level::DEBUG) << "IP needs to be updated";

                task_updateip(io_service, cfg.hostname, cfg.password, ssl_ctx);

                FILE_LOG(log_level::INFO) << "IP updated from " << externip_cached << " to " << externip;
            } else {
                FILE_LOG(log_level::DEBUG) << "IP does not need to be updated";
            }

            externip_cached = externip;
        }

    } catch (const std::exception & e) {
        FILE_LOG(log_level::ERROR) << e.what();
    }
}

static void daemon(const dtdnssync_config & cfg)
{
    asio::ip::address externip_cached;
    auto ssl_ctx = setup_ssl_context(cfg.cert_file);

    while (running) {
        run(cfg, externip_cached, ssl_ctx);

        FILE_LOG(log_level::DEBUG) << "sleeping";
        ::sleep(static_cast<unsigned int>(cfg.interval) * 60);
    }
}
