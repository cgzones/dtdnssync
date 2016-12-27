#include "dtdnssync.hpp"

#include <asio/io_service.hpp>
#include <asio/ssl/stream.hpp>
#include <asio/ssl/rfc2818_verification.hpp>
#include <asio/connect.hpp>

static asio::ssl::context setup_ssl_context(const std::string & cert_file);

std::vector<asio::ip::address> task_ip(const std::string & hostname) {
    asio::io_service io_service;
    asio::ip::tcp::resolver resolver { io_service };
    const asio::ip::tcp::resolver::query query { hostname, "" };

    std::vector<asio::ip::address> result;
    for(asio::ip::tcp::resolver::iterator i { resolver.resolve(query) };
                                i != asio::ip::tcp::resolver::iterator();
                                ++i)
    {
        const asio::ip::tcp::endpoint & end (*i);
        result.emplace_back(end.address());
    }

    return result;
}

asio::ip::address task_externip(const std::string & cert_file) {
    asio::io_service io_service;
    asio::ssl::context ctx { setup_ssl_context(cert_file) };
    asio::ssl::stream<asio::ip::tcp::socket> socket { io_service, ctx };
    asio::ip::tcp::resolver resolver { io_service };
    const asio::ip::tcp::resolver::query query { "myip.dtdns.com", "https" };

    asio::connect(socket.lowest_layer(), resolver.resolve(query));
    socket.lowest_layer().set_option(asio::ip::tcp::no_delay(true));
    socket.handshake(asio::ssl::stream<asio::ip::tcp::socket>::client);

    const std::string request {
            "GET / HTTP/1.0\r\n"
            "Host: myip.dtdns.com\r\n"
            "User-Agent: dtdnssync\r\n"
            "\r\n" };

    socket.write_some(asio::buffer(request));

    std::array<char, 256> buf {};
    std::ostringstream ostream;

    for(;;) {
        std::error_code ec;
        const auto len = socket.read_some(asio::buffer(buf), ec);

        if(ec == asio::error::eof) {
            break;
        } else if (ec) {
            throw asio::system_error(ec);
        }

        ostream.write(buf.data(), static_cast<std::streamsize>(len)); // ignore conversion warning size_t to long
    }

    const std::string response = ostream.str();

    if(response.compare(0, 15, "HTTP/1.1 200 OK") != 0) {
        throw std::runtime_error { "http: unsuccessful: " + response };
    }

    const auto pos = response.find("\r\n\r\n");
    if(pos == std::string::npos) {
        throw std::runtime_error { "http: no newline: " + response };
    }

    return asio::ip::address::from_string(trim(std::string { response, pos + 4, response.length() - (pos + 4) }));

}

void task_updateip(const std::string & hostname, const std::string & password, const std::string & cert_file) {
    asio::io_service io_service;
    asio::ssl::context ctx { setup_ssl_context(cert_file) };
    asio::ssl::stream<asio::ip::tcp::socket> socket { io_service, ctx };
    asio::ip::tcp::resolver resolver { io_service };
    const asio::ip::tcp::resolver::query query { "www.dtdns.com", "https" };

    asio::connect(socket.lowest_layer(), resolver.resolve(query));
    socket.lowest_layer().set_option(asio::ip::tcp::no_delay(true));
    socket.handshake(asio::ssl::stream<asio::ip::tcp::socket>::client);

    const std::string request {
            "GET /api/autodns.cfm?id=" + hostname + "&pw=" + password + "&client=dtdnssync HTTP/1.0\r\n"
            "Host: www.dtdns.com\r\n"
            "User-Agent: dtdnssync\r\n"
            "\r\n" };

    socket.write_some(asio::buffer(request));

    std::array<char, 256> buf {};
    std::ostringstream ostream;

    for(;;) {
        std::error_code ec;
        const auto len = socket.read_some(asio::buffer(buf), ec);

        if(ec == asio::error::eof) {
            break;
        } else if (ec) {
            throw asio::system_error(ec);
        }

        ostream.write(buf.data(), static_cast<std::streamsize>(len)); // ignore conversion warning size_t to long
    }

    const std::string response = ostream.str();

    if(response.compare(0, 15, "HTTP/1.1 200 OK") != 0) {
        throw std::runtime_error { "http: unsuccessful: " + response };
    }

    const auto pos = response.find("\r\n\r\n");
    if(pos == std::string::npos) {
        throw std::runtime_error { "http: no newline: " + response };
    }

    std::string response_content { response, pos + 4, response.length() - (pos + 4) };

    response_content = trim(response_content);

    const std::string expected { "Host " + hostname + " now points to " };

    if(response_content.compare(0, expected.length(), expected) != 0) {
        throw std::runtime_error { "unexpected dtdns response: " + response_content };
    }
}

static asio::ssl::context setup_ssl_context(const std::string & cert_file) {
    asio::ssl::context ctx { asio::ssl::context::tlsv12 };
    ctx.set_verify_mode(asio::ssl::verify_peer | asio::ssl::verify_fail_if_no_peer_cert );
    ctx.set_verify_callback(asio::ssl::rfc2818_verification{"www.dtdns.com"});
    ctx.load_verify_file(cert_file);

    return ctx;
}


