#include "dtdnssync.hpp"

#include <asio/connect.hpp>
#include <asio/ssl/rfc2818_verification.hpp>
#include <asio/ssl/stream.hpp>

std::vector<asio::ip::address> task_ip(asio::io_service& io_service,
                                       const std::string& hostname) {
  asio::ip::tcp::resolver resolver{io_service};
  const asio::ip::tcp::resolver::query query{hostname, ""};

  std::vector<asio::ip::address> result;
  for (asio::ip::tcp::resolver::iterator i{resolver.resolve(query)};
       i != asio::ip::tcp::resolver::iterator(); ++i) {
    const asio::ip::tcp::endpoint& end(*i);
    result.emplace_back(end.address());
  }

  return result;
}

asio::ip::address task_externip(asio::io_service& io_service,
                                asio::ssl::context& ssl_ctx) {
  asio::ssl::stream<asio::ip::tcp::socket> socket{io_service, ssl_ctx};
  asio::ip::tcp::resolver resolver{io_service};
  const asio::ip::tcp::resolver::query query{"myip.dtdns.com", "https"};

  asio::connect(socket.lowest_layer(), resolver.resolve(query));
  socket.lowest_layer().set_option(asio::ip::tcp::no_delay(true));
  socket.handshake(asio::ssl::stream<asio::ip::tcp::socket>::client);

  const std::string request{
      "GET / HTTP/1.0\r\n"
      "Host: myip.dtdns.com\r\n"
      "User-Agent: dtdnssync\r\n"
      "\r\n"};

  socket.write_some(asio::buffer(request));

  std::array<char, 256> buf{};
  std::ostringstream ostream;

  for (;;) {
    std::error_code ec;
    const auto len = socket.read_some(asio::buffer(buf), ec);

    if (ec == asio::error::eof) {
      break;
    } else if (ec) {
      throw asio::system_error(ec);
    }

    ostream.write(buf.data(),
                  static_cast<std::streamsize>(
                      len));  // ignore conversion warning size_t to long
  }

  const std::string response = ostream.str();

  const auto pos1 = response.find("\r\n");
  if (pos1 == std::string::npos) {
    throw std::runtime_error{"http: no newline: " + response};
  }
  const std::string first_line = response.substr(0, pos1);

  if (first_line != "HTTP/1.1 200 OK") {
    throw std::runtime_error{"http: unsuccessful: " + first_line};
  }

  const auto pos2 = response.find("\r\n\r\n");
  if (pos2 == std::string::npos) {
    throw std::runtime_error{"http: no double newline: " + response};
  }

  return asio::ip::address::from_string(
      trim(std::string{response, pos2 + 4, response.length() - (pos2 + 4)}));
}

void task_updateip(asio::io_service& io_service, const std::string& hostname,
                   const std::string& password, asio::ssl::context& ssl_ctx) {
  asio::ssl::stream<asio::ip::tcp::socket> socket{io_service, ssl_ctx};
  asio::ip::tcp::resolver resolver{io_service};
  const asio::ip::tcp::resolver::query query{"www.dtdns.com", "https"};

  asio::connect(socket.lowest_layer(), resolver.resolve(query));
  socket.lowest_layer().set_option(asio::ip::tcp::no_delay(true));
  socket.handshake(asio::ssl::stream<asio::ip::tcp::socket>::client);

  const std::string request{"GET /api/autodns.cfm?id=" + hostname +
                            "&pw=" + password +
                            "&client=dtdnssync HTTP/1.0\r\n"
                            "Host: www.dtdns.com\r\n"
                            "User-Agent: dtdnssync\r\n"
                            "\r\n"};

  socket.write_some(asio::buffer(request));

  std::array<char, 256> buf{};
  std::ostringstream ostream;

  for (;;) {
    std::error_code ec;
    const auto len = socket.read_some(asio::buffer(buf), ec);

    if (ec == asio::error::eof) {
      break;
    } else if (ec) {
      throw asio::system_error(ec);
    }

    ostream.write(buf.data(),
                  static_cast<std::streamsize>(
                      len));  // ignore conversion warning size_t to long
  }

  const std::string response = ostream.str();

  const auto pos1 = response.find("\r\n");
  if (pos1 == std::string::npos) {
    throw std::runtime_error{"http: no newline: " + response};
  }
  const std::string first_line = response.substr(0, pos1);

  if (first_line != "HTTP/1.1 200 OK") {
    throw std::runtime_error{"http: unsuccessful: " + first_line};
  }

  const auto pos2 = response.find("\r\n\r\n");
  if (pos2 == std::string::npos) {
    throw std::runtime_error{"http: no double newline: " + response};
  }

  std::string response_content =
      trim(response.substr(pos2 + 4, response.length() - (pos2 + 4)));

  const std::string expected{"Host " + hostname + " now points to "};

  if (response_content.compare(0, expected.length(), expected) != 0) {
    throw std::runtime_error{"unexpected dtdns response: " + response_content};
  }
}

asio::ssl::context setup_ssl_context(const std::string& cert_file) {
  asio::ssl::context ctx{asio::ssl::context::tlsv12};
  ctx.set_verify_mode(asio::ssl::verify_peer |
                      asio::ssl::verify_fail_if_no_peer_cert);
  ctx.set_verify_callback(asio::ssl::rfc2818_verification{"www.dtdns.com"});
  try {
    ctx.load_verify_file(cert_file);
  } catch (std::exception& e) {
    throw std::runtime_error{"Can not load certificate from " + cert_file +
                             ": " + e.what()};
  }

  return ctx;
}
