#include <fstream>

#include "dtdnssync.hpp"

static bool parse_bool(const std::string & value) {
    if(value == "1" or value == "true" or value == "True" or value == "TRUE") {
        return true;
    }

    if(value == "0" or value == "false" or value == "False" or value == "FALSE") {
        return false;
    }

    throw std::runtime_error { "Invalid boolean value " + value };
}

dtdnssync_config parse_config(const std::string & cfg_path) {
    std::ifstream cfg_file { cfg_path };
    if(!cfg_file.is_open()) {
        throw std::runtime_error { "Can not open configuration file " + cfg_path + ": " + ::strerror(errno)};
    }

    dtdnssync_config cfg;

    std::string line;

    while(std::getline(cfg_file, line)) {
        if(line.empty()) {
	    continue;
	}

	// ignore comment lines with leading #
	{
	    std::string::size_type position { 0 };
	    while(std::isspace(line[0]) != 0) {
		++position;
	    }
	    if(line[position] == '#') {
		continue;
	    }
	}

	auto eq_pos = line.find('=');
	if(eq_pos == std::string::npos) {
	    throw std::runtime_error { "Parse error, invalid line: " + line };
	}

	std::string key = trim(line.substr(0, eq_pos));
	std::string value = trim(line.substr(eq_pos + 1));

	if(key == "interval") {
	    const auto interval = std::strtoul(value.c_str(), nullptr, 10);
	    if(interval == ULONG_MAX or interval == 0 or interval == ULLONG_MAX) {
		throw std::runtime_error { "Parse error, invalid interval value: " + value };
	    } else if(interval > 10080) { // more than a week
		throw std::runtime_error { "Parse error, interval value to big (> 10080): " + value };
	    }

	    cfg.interval = interval;
	} else if (key == "hostname") {
	    cfg.hostname = remove_quotes(value);
	} else if (key == "password") {
	    cfg.password = remove_quotes(value);
	} else if (key == "cert_file") {
	    cfg.cert_file = remove_quotes(value);
	} else if (key == "cache_external_ip") {
	    cfg.cache_external_ip = parse_bool(value);
	} else if (key == "debug") {
	    cfg.debug = parse_bool(value);
	} else {
	    throw std::runtime_error { "Parse error, unknown key: " + key };
	}
    }

    return cfg;
}
