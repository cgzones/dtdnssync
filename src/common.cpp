#include "dtdnssync.hpp"

std::string remove_quotes(const std::string & str) {
	if (str.size() >= 2
			&& ((str[0] == '\'' && str[str.size() - 1] == '\'')
					|| (str[0] == '"' && str[str.size() - 1] == '"'))) {
		return str.substr(1, str.size() - 2);
	}
	return str;
}

std::string trim(const std::string & str) {
	std::string::size_type begin = 0, end = str.size() - 1;
	while (begin < end && std::isspace(str[begin]) != 0) {
		++begin;
	}

	while (end > begin && std::isspace(str[end]) != 0) {
		--end;
	}

	return str.substr(begin, end - begin + 1);
}
