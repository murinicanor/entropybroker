# GPL 2 applies to entropybroker.
# In addition, as a special exception, the copyright holders give
# permission to link the code of portions of this program with the
# OpenSSL library under certain conditions as described in each
# individual source file, and distribute linked combinations
# including the two.
# You must obey the GNU General Public License in all respects
# for all of the code used other than OpenSSL.  If you modify
# file(s) with this exception, you may extend this exception to your
# version of the file(s), but you are not obligated to do so.  If you
# do not wish to do so, delete this exception statement from your
# version.  If you delete this exception statement from all source
# files in the program, then also delete it here.
VERSION=1.1-rc2

PREFIX=/usr/local/entropybroker
BIN=$(PREFIX)/bin
ETC=$(PREFIX)/etc
VAR=$(PREFIX)/var
CACHE=$(VAR)/cache
PID=$(VAR)/run

CXX=g++
DEBUG= #-D_DEBUG #-fprofile-arcs -ftest-coverage # -pg
LINT=-Wshadow -Wall # -W -Wconversion -Wwrite-strings -Wunused
#CXXFLAGS+=-O3 -g3 -ggdb -march=native -mtune=native -DVERSION=\"${VERSION}\" $(LINT) $(DEBUG) -DCONFIG=\"${ETC}/entropy_broker.conf\" -DCACHE_DIR=\"${CACHE}\" -DPID_DIR=\"${PID}\"
CXXFLAGS+=-O3 -g3 -ggdb -march=native -mtune=native -DVERSION=\"${VERSION}\" $(LINT) $(DEBUG) -DCONFIG=\"${ETC}/entropy_broker.conf\" -DCACHE_DIR=\"${CACHE}\" -DPID_DIR=\"${PID}\" -DVAR_DIR=\"${VAR}\" -rdynamic
LDFLAGS+=$(DEBUG) -lcrypto -lrt -lz -lutil -rdynamic

BINARIES=entropy_broker eb_server_audio eb_server_timers eb_server_v4l eb_server_stream eb_client_linux_kernel eb_server_egd eb_client_egd eb_server_linux_kernel eb_client_file eb_server_push_file eb_server_ext_proc eb_server_usb plot eb_server_ComScire_R2000KU proxy_knuth

OBJSeb=pools.o handle_client.o config.o error.o fips140.o kernel_prng_rw.o log.o protocol.o main.o math.o pool.o scc.o signals.o utils.o auth.o my_pty.o ivec.o kernel_prng_io.o hasher.o stirrer.o hasher_sha512.o stirrer_blowfish.o stirrer_aes.o hasher_md5.o hasher_ripemd160.o stirrer_3des.o stirrer_camellia.o hasher_whirlpool.o users.o
OBJSsa=server_audio.o error.o utils.o kernel_prng_rw.o log.o protocol.o server_utils.o auth.o my_pty.o kernel_prng_io.o users.o
OBJSst=server_timers.o log.o utils.o error.o kernel_prng_rw.o protocol.o server_utils.o auth.o my_pty.o kernel_prng_io.o users.o
OBJSsv=server_v4l.o error.o log.o protocol.o kernel_prng_rw.o utils.o server_utils.o auth.o my_pty.o kernel_prng_io.o users.o
OBJSss=server_stream.o error.o log.o protocol.o kernel_prng_rw.o utils.o server_utils.o auth.o my_pty.o kernel_prng_io.o users.o
OBJSse=server_egd.o error.o log.o kernel_prng_rw.o protocol.o utils.o server_utils.o auth.o my_pty.o kernel_prng_io.o users.o
OBJSclk=client_linux_kernel.o error.o kernel_prng_io.o kernel_prng_rw.o log.o protocol.o utils.o auth.o my_pty.o math.o users.o
OBJScle=client_egd.o error.o log.o kernel_prng_io.o kernel_prng_rw.o math.o protocol.o utils.o auth.o my_pty.o users.o
OBJSsk=server_linux_kernel.o utils.o kernel_prng_rw.o kernel_prng_io.o log.o error.o protocol.o server_utils.o auth.o my_pty.o users.o
OBJScf=client_file.o error.o log.o kernel_prng_io.o kernel_prng_rw.o math.o protocol.o utils.o auth.o my_pty.o users.o
OBJSpf=server_push_file.o utils.o kernel_prng_rw.o kernel_prng_io.o log.o error.o protocol.o server_utils.o auth.o my_pty.o users.o
OBJSep=server_ext_proc.o utils.o kernel_prng_rw.o kernel_prng_io.o log.o error.o protocol.o server_utils.o auth.o my_pty.o users.o
OBJSsu=server_usb.o utils.o kernel_prng_rw.o kernel_prng_io.o log.o error.o protocol.o server_utils.o auth.o my_pty.o users.o
OBJScsr2000ku=server_ComScire_R2000KU.o utils.o kernel_prng_rw.o kernel_prng_io.o log.o error.o protocol.o server_utils.o auth.o my_pty.o users.o
OBJSpk=proxy_knuth.o utils.o kernel_prng_rw.o kernel_prng_io.o log.o error.o protocol.o server_utils.o auth.o my_pty.o users.o

all:
	@echo targets:
	@echo -------
	@echo All targets \(except from 'plot'\) require the OpenSSL libraries.
	@echo
	@echo entropy_broker          - main daemon which distributes the entropy data
	@echo
	@echo eb_server_audio         - retrieves noise from an audio device
	@echo                         = requires libasound2-dev
	@echo                         = linux only
	@echo
	@echo eb_server_timers        - retrieves entropy by comparing jitter of timers
	@echo
	@echo eb_server_v4l           - retrieves noise from video4linux2 devices \(webcams etc\)
	@echo                         = linux only
	@echo
	@echo eb_server_stream        - retrieves entropy data from a serial port or a hardware rng
	@echo
	@echo eb_server_egd           - retrieves entropy data from an EGD services \(e.g. entropykey\)
	@echo
	@echo eb_server_push_file     - push the contents of a file to the broker
	@echo
	@echo eb_server_ext_proc      - invoke a program/script/etc. and use its output
	@echo
	@echo eb_server_usb           - measure clock-jitter between system- and USB device clock
	@echo                         = requires libusb-1.0-0-dev
	@echo
	@echo eb_server_linux_kernel  - retrieves\(\!\) entropy data from a /dev/random device
	@echo                         = linux only
	@echo
	@echo eb_client_linux_kernel  - sends\(\!\) entropy data to a linux kernel
	@echo                         = linux only
	@echo
	@echo eb_client_file          - send entropy data to a file
	@echo eb_client_kernel_generic - send data to a generic kernel \(e.g. macos x/freebsd\)
	@echo
	@echo eb_client_egd           - send entropy data to a EGD client \(e.g. OpenSSL\)
	@echo
	@echo eb_server_ComScire_R2000KU - retrieves entropy data from a ComScire R2000KU
	@echo                         = requires libftdi-dev
	@echo
	@echo OBJSpk
	@echo
	@echo plot                    - plot random data: patterns=bad. use with e.g. eb_client_file
	@echo                         = requires libpng-dev
	@echo
	@echo invoke:
	@echo	make everything
	@echo to build all daemons
	@echo invoke:
	@echo	make install
	@echo to install all daemons etc. under $(PREFIX)
	@echo

everything: $(BINARIES)

entropy_broker: $(OBJSeb)
	$(CXX) $(LINT) $(OBJSeb) $(LDFLAGS) -o entropy_broker

eb_server_audio: $(OBJSsa)
	$(CXX) $(LINT) $(OBJSsa) $(LDFLAGS) -lasound -o eb_server_audio

eb_server_timers: $(OBJSst)
	$(CXX) $(LINT) $(OBJSst) $(LDFLAGS) -o eb_server_timers

eb_server_v4l: $(OBJSsv)
	$(CXX) $(LINT) $(OBJSsv) $(LDFLAGS) -o eb_server_v4l

eb_server_stream: $(OBJSss)
	$(CXX) $(LINT) $(OBJSss) $(LDFLAGS) -o eb_server_stream

eb_server_egd: $(OBJSse)
	$(CXX) $(LINT) $(OBJSse) $(LDFLAGS) -o eb_server_egd

eb_client_egd: $(OBJScle)
	$(CXX) $(LINT) $(OBJScle) $(LDFLAGS) -o eb_client_egd

eb_client_linux_kernel: $(OBJSclk)
	$(CXX) $(LINT) $(OBJSclk) $(LDFLAGS) -o eb_client_linux_kernel

eb_server_linux_kernel: $(OBJSsk)
	$(CXX) $(LINT) $(OBJSsk) $(LDFLAGS) -o eb_server_linux_kernel

eb_client_file: $(OBJScf)
	$(CXX) $(LINT) $(OBJScf) $(LDFLAGS) -o eb_client_file

eb_server_push_file: $(OBJSpf)
	$(CXX) $(LINT) $(OBJSpf) $(LDFLAGS) -o eb_server_push_file

eb_server_ext_proc: $(OBJSep)
	$(CXX) $(LINT) $(OBJSep) $(LDFLAGS) -o eb_server_ext_proc

eb_server_usb: $(OBJSsu)
	$(CXX) $(LINT) $(OBJSsu) $(LDFLAGS) -lusb-1.0 -o eb_server_usb

eb_server_ComScire_R2000KU: $(OBJScsr2000ku)
	$(CXX) $(LINT) $(OBJScsr2000ku) ComScire_R2000KU/qwqng.cpp $(LDFLAGS) -lftdi -o eb_server_ComScire_R2000KU

proxy_knuth: $(OBJSpk)
	$(CXX) $(LINT) $(OBJSpk) $(LDFLAGS) -o proxy_knuth

plot: plot.o
	$(CXX) $(LINT) plot.o $(LDFLAGS) -lpng -o plot

install: everything
	mkdir -p $(BIN) $(ETC) $(VAR) $(PID) $(CACHE)
	for file in $(BINARIES) ; do \
		test -e $(file) && cp $$file $(BIN) ; \
	done
	test -e $(BIN)/eb_client_file && \
		(test -e $(BIN)/eb_client_kernel_generic || \
		ln $(BIN)/eb_client_file $(BIN)/eb_client_kernel_generic)
	test -e $(ETC)/entropy_broker.conf || cp entropy_broker.conf $(ETC)
	test -e $(ETC)/entropy_broker.conf && cp entropy_broker.conf $(ETC)/entropy_broker.conf.dist
	test -e $(ETC)/users.txt || (cp users.txt $(ETC) ; chmod 600 $(ETC)/users.txt)

clean:
	rm -f $(OBJSeb) $(OBJSsa) $(OBJSst) $(OBJSsv) $(OBJSss)$(OBJSse) $(OBJSclk) $(OBJSte) $(OBJSsk) $(OBJScf) $(OBJSpf) $(OBJSep) $(OBJSsu) $(OBJScsr2000ku) $(OBJScle) $(OBJSse) $(OBJSpk) plot.o core *.da *.gcov *.bb* $(BINARIES)

package:
	mkdir eb-$(VERSION) eb-$(VERSION)/ComScire_R2000KU
	cp *.cpp *.h entropy_broker.conf Makefile Changes auth.txt users.txt readme.txt design.txt interfacing.txt license.* eb-$(VERSION)
	cp ComScire_R2000KU/*.[ch]pp ComScire_R2000KU/LICENSE eb-$(VERSION)/ComScire_R2000KU
	tar cf - doc --exclude=.svn  | tar xvf - -C eb-$(VERSION)
	tar czf eb-$(VERSION).tgz eb-$(VERSION)
	rm -rf eb-$(VERSION)
	#
	cp design.txt ~/site/entropybroker/

coverity: clean
	rm -rf cov-int
	cov-build --dir cov-int make everything
	tar vczf ~/site/coverity/EntropyBroker.tgz README cov-int/
	putsite -q
	/home/folkert/.coverity-eb.sh

check:
	cppcheck -v --enable=all --std=c++11 --inconclusive . 2> err.txt
