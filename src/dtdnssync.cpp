#include "dtdnssync.hpp"

#include <iostream>

int main(int argc, char ** argv) {

  std::string cfg_path { "/etc/dtdnssync/dtdnssync.cfg" };
  int argc_progress = 1;

 if(argc < 2) {
    std::cerr << "No command given! Try " << argv[0] << " help\n";
    return EXIT_FAILURE;
  }

  if(::strcmp(argv[1],"help") == 0 or ::strcmp(argv[1], "-h") == 0 or ::strcmp(argv[1], "--help") == 0) {
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

  if(::strcmp(argv[argc_progress], "--cfg") == 0) {
      if(!argv[++argc_progress]) {
          std::cerr << "Option --cfg need an argument!\n";
          return EXIT_FAILURE;
      }
      cfg_path = argv[argc_progress];
      ++argc_progress;

      if(argc < 4) {
	std::cerr << "No command given! Try " << argv[0] << " help\n";
	return EXIT_FAILURE;
      } else if(argc > 4) {
	  std::cerr << "Invalid command given! Try " << argv[0] << " help\n";
	  return EXIT_FAILURE;
      }
  }

  dtdnssync_config cfg;

  try {
      cfg = parse_config(cfg_path);
  } catch(const std::exception & e) {
      std::cerr << "Can not parse config file " + cfg_path + ": " << e.what() << '\n';
      return EXIT_FAILURE;
  }

  if(::strcmp(argv[argc_progress], "version") == 0) {
    std::cout << version << '\n';

    return EXIT_SUCCESS;
  }
  else if(::strcmp(argv[argc_progress], "currentip") == 0) {
    try {
        std::vector<asio::ip::address> addresses = task_ip(cfg.hostname);
        std::cout << "address(es) for " << cfg.hostname << ":";
        for(const asio::ip::address & addr : addresses) {
            std::cout << " " << addr;
        }
        std::cout << "\n";

    } catch(const std::exception & e) {
        std::cerr << "Unable to get IP address for " << cfg.hostname << ": " << e.what() << '\n';
        return EXIT_FAILURE;
    }


    return EXIT_SUCCESS;
  }
  else if(::strcmp(argv[argc_progress], "externip") == 0) {
      try {
          auto ip = task_externip(cfg.cert_file);
          std::cout << "current external ip: " << ip << "\n";

      } catch(const std::exception & e) {
          std::cerr << "Unable to get external IP address: " << e.what() << '\n';
          return EXIT_FAILURE;
      }

      return EXIT_SUCCESS;
  }
  else if(::strcmp(argv[argc_progress], "dumpconfig") == 0) {
    std::cout << "configuration from file " + cfg_path + ":\n"
              << "  interval          : " << cfg.interval << '\n'
              << "  cache_external_ip : " << std::boolalpha << cfg.cache_external_ip << '\n'
              << "  cert_file         : " << cfg.cert_file << '\n'
	      << "  debug             : " << std::boolalpha << cfg.debug << '\n'
              << "  hostname          : " << cfg.hostname << '\n'
              << "  password          : " << cfg.password << '\n'
              << '\n';

    return EXIT_SUCCESS;
  }
  else if(::strcmp(argv[argc_progress], "update") == 0) {
      try {
          task_updateip(cfg.hostname, cfg.password, cfg.cert_file);
      } catch(const std::exception & e) {
          std::cerr << "Unable to update IP: " << e.what() << '\n';
          return EXIT_FAILURE;
      }

      std::cout << "IP address for " << cfg.hostname << " was successfully updated\n";

      return EXIT_SUCCESS;
  }
  else if(::strcmp(argv[argc_progress], "check") == 0) {
    try {
        auto externip = task_externip(cfg.cert_file);
        auto ips = task_ip(cfg.hostname);
        bool match { false };

        for(const auto & ip : ips) {
            if(ip == externip) {
		match = true; break;
	    }
        }

        if(match) {
            std::cout << "IP is up to date for " << cfg.hostname << " (" << externip << ")\n";
        } else {
            std::cout << "IP is out of date for " << cfg.hostname << " (dns: ";
            for(const auto & ip : ips) {
                std::cout << ip << " ";
            }
            std::cout << " current: " << externip << ")\n";
        }


    } catch(const std::exception & e) {
        std::cerr << "Unable to check for IP update: " << e.what() << '\n';
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
  }
  else
  {
      std::cerr << "Invalid option '" << argv[argc_progress] << "'! Try " << argv[0] << " help\n";
      return EXIT_FAILURE;
  }

}
