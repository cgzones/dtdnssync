#include "dtdnssync.hpp"

#include "logger.hpp"

#include <getopt.h>
#include <grp.h>
#include <iostream>
#include <pwd.h>
#include <signal.h>
#include <sys/types.h>


static void daemonize(const std::string & pidfile, const std::string & user, const std::string & group);
static void daemon(const dtdnssync_config & cfg);
static void signal_handler(int sig);

static volatile bool running = true;

int main(int argc, char ** argv) {

    std::string cfg_path { "/etc/dtdnssync/dtdnssync.cfg" };
    std::string pid_path { "/run/dtdnssyncd.pid" };
    std::string log_path { "/var/log/dtdnssyncd.log" };
    std::string user, group;
    int debug_flag = 0;

    while (true) {
        const struct option long_options[] = {
        { "debug"   , no_argument      , &debug_flag, 1   },
        { "cfg-file", required_argument, nullptr      , 'c' },
        { "log-file", required_argument, nullptr      , 'l' },
        { "pid-file", required_argument, nullptr      , 'p' },
        { "user"    , required_argument, nullptr      , 'u' },
        { "group"   , required_argument, nullptr      , 'g' },
	{ "version" , no_argument      , nullptr      , 'v' },
        { "help"    , no_argument      , nullptr      , 'h' },
        { nullptr   , 0                , nullptr      , 0   }
	};
        int option_index = 0;

        const int c = getopt_long(argc, argv, "c:hp:l:u:g:", long_options, &option_index);

        if (c == -1) { break; }

        switch (c) {
        case 0:
            if (long_options[option_index].flag != nullptr) { break; }
            printf("option %s", long_options[option_index].name);
            if (optarg != nullptr) {
                printf(" with arg %s", optarg);
	    }
            printf("\n");
            break;

        case 'c':
            cfg_path = optarg;
            break;

        case 'p':
            pid_path = optarg;
            break;

        case 'l':
            log_path = optarg;
            break;

        case 'u':
            user = optarg;
            break;

        case 'g':
            group = optarg;
            break;

        case 'h':
            std::cout << "dtdnssyncd " << version << '\n'
                      << "usage: " << argv[0] << " [options]\n"
                      << "\n"
                      << "  options:\n"
                      << "    --cfg-file PATH    use custom configuration file (default: " << cfg_path << ")\n"
                      << "    --pid-file PATH    specify pid file (default: " << pid_path << ")\n"
                      << "    --log-file PATH    specify log file (default: " << log_path << ")\n"
                      << "    --user USERNAME    run daemon as different user than root\n"
                      << "    --group GROUPNAME  run daemon as different group than root\n"
                      << "    --debug            turn on debug output\n"
		      << "    --version          display version and exit\n"
                      << "    --help             this help overview\n"
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
        for (;optind < argc; ++optind) {
            std::cerr << argv[optind];
        }
        std::cerr << '\n';
        std::cerr << "EXITING!!!\n";
        return EXIT_FAILURE;
    }

    dtdnssync_config cfg;

    try {
        cfg = parse_config(cfg_path);
    } catch (const std::exception & e) {
        std::cerr << "Can not parse config: " << e.what() << '\n';
        std::cerr << "EXITING!!!\n";
        return EXIT_FAILURE;
    }

    if(cfg.hostname.empty() or cfg.hostname == "yourdomain") {
	std::cerr << "Configuration: Hostname not set\n";
	std::cerr << "Exiting\n";
	return EXIT_SUCCESS;
    }

    FILELog::domain() = "dtdnssync";
    if(debug_flag == 1 or cfg.debug) { FILELog::reporting_level() = log_level::DEBUG; }
    else { FILELog::reporting_level() = log_level::INFO; }
    if((Output2FILE::stream() = ::fopen(log_path.c_str(), "a")) == nullptr) {
        std::cerr << "Can not open " << log_path << ": " << ::strerror(errno) << '\n';
        std::cerr << "EXITING!!!\n";
        return EXIT_FAILURE;
    }

    FILE_LOG(log_level::DEBUG) << "configuration:";
    FILE_LOG(log_level::DEBUG) << "  interval          : " << cfg.interval;
    FILE_LOG(log_level::DEBUG) << "  cache_external_ip : " << std::boolalpha << cfg.cache_external_ip;
    FILE_LOG(log_level::DEBUG) << "  cert_file         : " << cfg.cert_file;
    FILE_LOG(log_level::DEBUG) << "  debug             : " << std::boolalpha << cfg.debug;
    FILE_LOG(log_level::DEBUG) << "  hostname          : " << cfg.hostname;
    FILE_LOG(log_level::DEBUG) << "  password          : " << cfg.password;


    daemonize(pid_path, user, group);

    FILE_LOG(log_level::INFO) << "Starting for host '" << cfg.hostname << "' with an interval of " << cfg.interval << " minutes and ip caching "
                              << (cfg.cache_external_ip ? "enabled" : "disabled");

    daemon(cfg);

    FILE_LOG(log_level::INFO) << "ending";

    return EXIT_SUCCESS;

}

static void signal_handler(int sig) {
    switch(sig) {
    case SIGHUP:
        FILE_LOG(log_level::INFO) << "hangup signal caught";
        running = false;
        break;
    case SIGINT:
	FILE_LOG(log_level::INFO) << "interrupt signal caught";
	running = false;
	break;
    case SIGTERM:
        FILE_LOG(log_level::WARNING) << "terminate signal caught";
	FILE_LOG(log_level::WARNING) << "Exiting!";
        exit(0);
    }
}

static void daemonize(const std::string & pidfile, const std::string & user, const std::string & group) {

    {
        auto i = ::fork();
        if (i < 0) {
            FILE_LOG(log_level::ERROR) << "Can not fork: " << ::strerror(errno);
	    FILE_LOG(log_level::WARNING) << "Exiting!";
            exit(1);
        }
        if (i > 0) { exit(0); }
    }

    if(::setsid() < 0) {
        FILE_LOG(log_level::ERROR) << "Error calling setsid: " << ::strerror(errno);
	FILE_LOG(log_level::WARNING) << "Exiting!";
        exit(1);
    }

    ::signal(SIGCHLD, SIG_IGN);
    ::signal(SIGTSTP, SIG_IGN);
    ::signal(SIGTTOU, SIG_IGN);
    ::signal(SIGTTIN, SIG_IGN);
    ::signal(SIGINT , signal_handler);
    ::signal(SIGHUP , signal_handler);
    ::signal(SIGTERM, signal_handler);

    {
        auto i = ::fork();
        if (i < 0) {
            FILE_LOG(log_level::ERROR) << "Can not fork: " << ::strerror(errno);
	    FILE_LOG(log_level::WARNING) << "Exiting!";
            exit(1);
        }
        if (i > 0) { exit(0); }
    }

    {
        auto fd = ::open("/dev/null", O_RDWR);
        if(fd < 0) {
            FILE_LOG(log_level::ERROR) << "Can not open /dev/null: " << ::strerror(errno);
	    FILE_LOG(log_level::WARNING) << "Exiting!";
            exit(1);
        }

        ::dup2(fd, 0);
        ::dup2(fd, 1);
        ::dup2(fd, 2);
        ::close(fd);
    }

    ::umask(027);

    if (::chdir("/") == -1) {
        FILE_LOG(log_level::ERROR) << "Can not chdir to /: " << ::strerror(errno);
	FILE_LOG(log_level::WARNING) << "Exiting!";
        exit (1);
    }

    {
        auto pid_fd = open(pidfile.c_str(), O_WRONLY|O_CREAT, 0640);
        if (pid_fd < 0) {
            FILE_LOG(log_level::ERROR) << "Can not open " << pidfile << ": " << ::strerror(errno);
	    FILE_LOG(log_level::WARNING) << "Exiting!";
            exit(1);
        }

        struct flock fl {};
        fl.l_type   = F_WRLCK;
        fl.l_whence = SEEK_SET;
        fl.l_start  = 0;
        fl.l_len    = 0;
        fl.l_pid    = getpid();
        if(::fcntl(pid_fd, F_SETLK, &fl) < 0) {
            FILE_LOG(log_level::ERROR) << "Can not lock " << pidfile << ": " << ::strerror(errno);
            FILE_LOG(log_level::ERROR) << "Another instance is already running?";
	    FILE_LOG(log_level::WARNING) << "Exiting!";
            exit(1);
        }

        char pid[8];
        ::snprintf(pid, 8, "%u\n",getpid());

	if(::write(pid_fd, pid, ::strlen(pid)) <= 0) {
	    FILE_LOG(log_level::ERROR) << "Can not write into pid file " << pidfile << ": " << ::strerror(errno);
	    FILE_LOG(log_level::WARNING) << "Exiting!";
	    exit(1);
	}

        //::close(pid_fd); do not close to hold lock
    }

    if(!group.empty()) {
        const struct group *grp = ::getgrnam(group.c_str());
        if(grp == nullptr) {
            FILE_LOG(log_level::ERROR) << "Can not find group " << group << ": " << ::strerror(errno);
	    FILE_LOG(log_level::WARNING) << "Exiting!";
            exit(1);
        }

        if (::setgid(grp->gr_gid) < 0) {
            FILE_LOG(log_level::ERROR) << "Can not change to group " << group << ": " << ::strerror(errno);
	    FILE_LOG(log_level::WARNING) << "Exiting!";
            exit(1);
        }
    }

    if(!user.empty()) {
        const struct passwd *pw = ::getpwnam(user.c_str());
        if(pw == nullptr) {
            FILE_LOG(log_level::ERROR) << "Can not find user " << user << ": " << ::strerror(errno);
	    FILE_LOG(log_level::WARNING) << "Exiting!";
            exit(1);
        }

        if (::setuid(pw->pw_uid) < 0) {
            FILE_LOG(log_level::ERROR) << "Can not change to user " << user << ": " << ::strerror(errno);
	    FILE_LOG(log_level::WARNING) << "Exiting!";
            exit(1);
        }
    }

    if(::getuid() == 0) {
	FILE_LOG(log_level::WARNING) << "Running daemon as user root";
    } else if (::geteuid() == 0) {
	FILE_LOG(log_level::WARNING) << "Running daemon as effective user root";
    } else if (::getgid() == 0) {
	FILE_LOG(log_level::WARNING) << "Running daemon as group root";
    }
}

static void daemon(const dtdnssync_config & cfg) {
    asio::ip::address externip_cached;

    while(running) {
	FILE_LOG(log_level::DEBUG) << "running new check...";

        try {
            const auto externip = task_externip(cfg.cert_file);
            FILE_LOG(log_level::DEBUG) << "current extern IP: " << externip;
            if(cfg.cache_external_ip) {
		FILE_LOG(log_level::DEBUG) << "cached extern IP: " << externip_cached;
	    }

            if(cfg.cache_external_ip && (externip == externip_cached)) {
		FILE_LOG(log_level::DEBUG) << "extern IP not changed, no need to update IP";
	    } else {
                FILE_LOG(log_level::DEBUG) << "extern IP might have changed";


                const auto hostnameips = task_ip(cfg.hostname);
                FILE_LOG(log_level::DEBUG) << "hostname IPs: ";
                for(const auto & ip: hostnameips) {
                    FILE_LOG(log_level::DEBUG) << "- " << ip;
                }


                bool uptodate = false;
                for(const auto & ip: hostnameips) {
                    if(ip == externip) { uptodate = true; break; }
                }

                if(!uptodate) {
                    FILE_LOG(log_level::DEBUG) << "IP needs to be updated";

                    task_updateip(cfg.hostname, cfg.password, cfg.cert_file);

                    FILE_LOG(log_level::INFO) << "IP updated to " << externip;
                } else {
                    FILE_LOG(log_level::DEBUG) << "IP does not need to be updated";
                }

                if(cfg.cache_external_ip) {
		    externip_cached = externip;
		}
            }

        } catch(const std::exception & e) {
            FILE_LOG(log_level::ERROR) << e.what();
        }

        FILE_LOG(log_level::DEBUG) << "sleeping";
        ::sleep(static_cast<unsigned int>(cfg.interval) * 60);

    }
}
