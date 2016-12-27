#pragma once

#include <ctime>
#include <iomanip>
#include <sstream>
#include <unistd.h>

// Adopted from http://www.drdobbs.com/cpp/logging-in-c/201804215

enum class log_level {
    ERROR,
    WARNING,
    INFO,
    DEBUG
};

std::ostream & operator<<(std::ostream & out, const log_level & ll);

inline std::ostream & operator<<(std::ostream & out, const log_level & ll)
{
    switch (ll) {
    case log_level::ERROR:
        out << "ERROR ";
        break;
    case log_level::WARNING:
        out << "WARN  ";
        break;
    case log_level::INFO:
        out << "INFO  ";
        break;
    case log_level::DEBUG:
        out << "DEBUG ";
        break;
    }

    return out;
}

template <typename OutputPolicy>
class Log {
public:
    Log() = default;
    Log(const Log & other) = delete;
    Log & operator =(const Log & other) = delete;
    Log(Log && other) = delete;
    Log & operator =(Log && other) = delete;
    ~Log();


    std::ostringstream & get(const log_level & level = log_level::INFO);

    static log_level & reporting_level() noexcept {
        static log_level logLevel = log_level::INFO;
        return logLevel;
    }

    static const char *&domain() noexcept {
        static const char *domain = "unset";
        return domain;
    }


private:
    std::ostringstream m_os;

};


template <typename OutputPolicy>
std::ostringstream & Log<OutputPolicy>::get(const log_level & level)
{
    char time_buffer[32];
    const std::time_t now = std::time(nullptr);
    struct tm time {};

    std::strftime(time_buffer, sizeof(time_buffer), "%c %Z",
                  ::localtime_r(&now, &time));
    m_os << time_buffer;
    m_os << ' ' << std::setw(16) << Log::domain();

    m_os << ' ' << std::setw(4) << ::getpid();

    if (reporting_level() >= log_level::DEBUG) {
        m_os << ' ' << ::pthread_self();
    }

    m_os << ' ' << level << ": ";
    return m_os;
}

template <typename OutputPolicy>
Log<OutputPolicy>::~Log()
{
    m_os << std::endl;

    OutputPolicy::output(m_os.str());
}

class Output2FILE { // implementation of OutputPolicy
public:
    static FILE *&stream() noexcept;
    static void output(const std::string & msg) noexcept;
};

inline FILE *&Output2FILE::stream() noexcept {
    static FILE *pStream = ::stderr;
    return pStream;
}

inline void Output2FILE::output(const std::string & msg) noexcept {
    FILE *pStream = stream();

    ::fprintf(pStream, "%s", msg.c_str());
    ::fflush(pStream);
}

using FILELog = Log<Output2FILE>;

#define FILE_LOG(level) \
    if ((level) > FILELog::reporting_level()) ; \
    else FILELog().get(level)
