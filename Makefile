# dirs
SBIN    ?= ${DESTDIR}/usr/sbin
ETC     ?= ${DESTDIR}/etc
SHARE   ?= ${DESTDIR}/usr/share

#general flags
CXXFLAGS += -std=c++14

# asio flags
CXXFLAGS += -DASIO_STANDALONE -DASIO_NO_DEPRECATED -DASIO_NO_TYPEID -DASIO_DISABLE_BUFFER_DEBUGGING

# security flags
CXXFLAGS += -Wall -Wextra -Wpedantic -Wconversion -Wformat -Wformat-security -Werror
CXXFLAGS += -O2 -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2

# library link flags
LDFLAGS += -lpthread -lssl -lcrypto

# security link flags
LDFLAGS += -fPIE -pie -Wl,-z,relro -Wl,-z,now -Wl,--no-undefined

ifdef MODE
ifeq (${MODE}, DEV)
	CXX = clang++
	CXXFLAGS += -g -Weverything -Wno-c++98-compat -Wno-c++98-compat-pedantic -Wno-padded -fsanitize=address,undefined
else
ifeq (${MODE}, DEBUG)
	CXXFLAGS += -g
endif # DEBUG
endif # DEV
endif # MODE

.PHONY: all default doc clean install run_cppcheck run_clang-tidy debian_package run_lintian pretty

default: dtdnssync dtdnssyncd
all: default doc

OBJS = src/common.o src/config.o src/dtdns_driver.o
HEAD = src/dtdnssync.hpp

dtdnssync: src/dtdnssync.o ${OBJS} ${HEAD}
	${CXX} ${CXXFLAGS} $< ${OBJS} ${LDFLAGS} -o $@

dtdnssyncd: src/dtdnssyncd.o ${OBJS} ${HEAD}
	${CXX} ${CXXFLAGS} $< ${OBJS} ${LDFLAGS} -o $@

%.o: %.cpp ${HEAD}
	${CXX} ${CXXFLAGS} -c $< -o $@

DOCS = man/dtdnssync.8.adoc man/dtdnssyncd.8.adoc man/dtdnssync.conf.5.adoc
doc: ${DOCS} man/footer.adoc
	asciidoctor -b manpage -v ${DOCS}

clean:
	rm -f dtdnssync dtdnssyncd src/*.o
	rm -Rf debian/.debhelper
	rm -f debian/debhelper-build-stamp
	rm -f debian/dtdnssync.debhelper.log
	rm -f debian/dtdnssync.substvars
	rm -f debian/files
	rm -Rf debian/dtdnssync
	rm -f debian/*.debhelper
	rm -f man/dtdnssync.8 man/dtdnssyncd.8 man/dtdnssync.conf.5

install: default
	install -m 0750 -d ${ETC}/dtdnssync/
	install -m 0640 cfg/dtdnssync.conf ${ETC}/dtdnssync/
	install -m 0755 -d ${SHARE}/dtdnssync/
	install -m 0440 cfg/dtdns.pem ${SHARE}/dtdnssync/

	install -m 0755 dtdnssync ${SBIN}
	install -m 0755 dtdnssyncd ${SBIN}

fixperms:
	chown :dtdnssync ${ETC}/dtdnssync/ ${ETC}/dtdnssync/dtdnssync.conf


run_cppcheck:
	cppcheck --force --enable=style --enable=missingInclude --inconclusive --std=c++11 --std=posix --library=std.cfg --library=posix.cfg --check-library --inline-suppr -j4 --error-exitcode=3 src/

run_clang-tidy:
	clang-tidy -header-filter=.* -checks=* src/*.cpp -- -std=c++14 -DASIO_STANDALONE -DASIO_NO_DEPRECATED -DASIO_NO_TYPEID

debian_package:
	debuild -nc -us -uc

run_lintian:
	lintian -i -I -E --pedantic --show-overrides ../dtdnssync*.changes

pretty:
	clang-format -i -style=file src/*
