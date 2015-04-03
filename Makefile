# dirs
SBIN    ?= ${DESTDIR}/usr/sbin
ETC     ?= ${DESTDIR}/etc
SHARE   ?= ${DESTDIR}/usr/share

#general flags
CXXFLAGS = -std=c++14
CXXFLAGS += -flto

# asio flags
CXXFLAGS += -DASIO_STANDALONE -DASIO_NO_DEPRECATED

# security flags
CXXFLAGS += -Wall -Wextra -Wpedantic -Wconversion -Wformat -Wformat-security -Werror
CXXFLAGS += -O2 -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2

# library link flags
LDFLAGS = -lpthread -lssl -lcrypto

# security link flags
LDFLAGS += -fPIE -pie -Wl,-z,relro -Wl,-z,now -Wl,--no-undefined

ifdef DEV
	CXX = clang++
	CXXFLAGS += -g -Weverything -Wno-c++98-compat -Wno-c++98-compat-pedantic -Wno-padded -fsanitize=address,undefined
endif

.PHONY: all clean install run_cppcheck run_clang-tidy

all: dtdnssync dtdnssyncd

dtdnssync: src/dtdnssync.o src/common.o src/config.o src/dtdns_driver.o
	${CXX} ${CXXFLAGS} $^ ${LDFLAGS} -o $@
	
dtdnssyncd: src/dtdnssyncd.o src/common.o src/config.o src/dtdns_driver.o
	${CXX} ${CXXFLAGS} $^ ${LDFLAGS} -o $@
	
.cpp.o:
	${CXX} ${CXXFLAGS} -c $< -o $@
	
clean:
	rm -f dtdnssync dtdnssyncd src/*.o
	rm -Rf debian/.debhelper
	rm -f debian/debhelper-build-stamp
	rm -f debian/dtdnssync.debhelper.log
	rm -f debian/dtdnssync.substvars
	rm -f debian/files
	rm -Rf debian/dtdnssync
	rm -f debian/*.debhelper

install: all
	install -m 0600 cfg/dtdnssync.cfg ${ETC}/dtdnssync/dtdnssync.cfg
	install -m 0440 cfg/dtdns.pem ${SHARE}/dtdnssync/dtdns.pem

	install -m 0755 dtdnssync ${SBIN}
	install -m 0755 dtdnssyncd ${SBIN}

run_cppcheck:
	cppcheck --quiet --force --enable=style --enable=missingInclude --inconclusive --std=c++11 --std=posix --library=std.cfg --library=posix.cfg --check-library -j4 src/

run_clang-tidy:
	clang-tidy -header-filter=.* -checks=* src/*.cpp -- -std=c++14 -DASIO_STANDALONE -DASIO_NO_DEPRECATED
