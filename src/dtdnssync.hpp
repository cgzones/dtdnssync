#pragma once

#include <asio/ip/tcp.hpp>
#include <asio/io_service.hpp>

#include <string>
#include <vector>

constexpr const char* version = "0.1_dev";

std::string remove_quotes(const std::string & str);

std::string trim(const std::string & str);

struct dtdnssync_config {
	std::string hostname;
	std::string password;
	std::string cert_file { "/usr/share/dtdnssync/dtdns.pem" };
	unsigned long interval { 6 };
	bool debug { false };
};

dtdnssync_config parse_config(const std::string & cfg_path);

std::vector<asio::ip::address> task_ip(asio::io_service& io_service,
		const std::string & hostname);
asio::ip::address task_externip(asio::io_service& io_service,
		const std::string & cert_file);
void task_updateip(asio::io_service& io_service, const std::string & hostname,
		const std::string & password,
		const std::string & cert_file);
