# dirs
SBIN    ?= ${DESTDIR}/usr/sbin
ETC     ?= ${DESTDIR}/etc
SHARE   ?= ${DESTDIR}/usr/share

#general flags
CXXFLAGS = -std=c++14

# asio flags
CXXFLAGS += -DASIO_STANDALONE -DASIO_NO_DEPRECATED -DASIO_NO_TYPEID

# security flags
CXXFLAGS += -Wall -Wextra -Wpedantic -Wconversion -Wformat -Wformat-security -Werror
CXXFLAGS += -O2 -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2

# library link flags
LDFLAGS = -lpthread -lssl -lcrypto

# security link flags
LDFLAGS += -fPIE -pie -Wl,-z,relro -Wl,-z,now -Wl,--no-undefined

ifdef MODE
ifeq (${MODE}, DEV)
	CXX = clang++
	CXXFLAGS += -g -Weverything -Wno-c++98-compat -Wno-c++98-compat-pedantic -Wno-padded -fsanitize=address,undefined
else
ifeq (${MODE}, DEBUG)
	CXXFLAGS += -g
else
ifeq (${MODE}, RELEASE)
	CXXFLAGS += -flto -DASIO_DISABLE_BUFFER_DEBUGGING
endif # RELEASE
endif # DEBUG
endif # DEV
endif # MODE

.PHONY: all clean install run_cppcheck run_clang-tidy debian_package debian_orig_tarball

all: dtdnssync dtdnssyncd

OBJS = src/common.o src/config.o src/dtdns_driver.o
HEAD = src/dtdnssync.hpp

dtdnssync: src/dtdnssync.o ${OBJS} ${HEAD}
	${CXX} ${CXXFLAGS} $< ${OBJS} ${LDFLAGS} -o $@
	
dtdnssyncd: src/dtdnssyncd.o ${OBJS} ${HEAD}
	${CXX} ${CXXFLAGS} $< ${OBJS} ${LDFLAGS} -o $@
	
%.o: %.cpp ${HEAD}
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
	install -m 0640 cfg/dtdnssync.cfg ${ETC}/dtdnssync/
	install -m 0440 cfg/dtdns.pem ${SHARE}/dtdnssync/

	install -m 0755 dtdnssync ${SBIN}
	install -m 0755 dtdnssyncd ${SBIN}

run_cppcheck:
	cppcheck --quiet --force --enable=style --enable=missingInclude --inconclusive --std=c++11 --std=posix --library=std.cfg --library=posix.cfg --check-library --inline-suppr -j4 src/

run_clang-tidy:
	clang-tidy -header-filter=.* -checks=* src/*.cpp -- -std=c++14 -DASIO_STANDALONE -DASIO_NO_DEPRECATED -DASIO_NO_TYPEID

debian_orig_tarball:
	GZIP="-9n" tar zfc ../dtdnssync_0.1.orig.tar.gz --sort=name cfg/ debian/ LICENSE Makefile README.md src/ VERSION .cproject .project .travis.yml .settings/

debian_package:
	dpkg-buildpackage -nc -b -us -uc
