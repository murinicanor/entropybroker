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
VERSION=1.1

PREFIX=/usr/local/entropybroker
BIN=$(PREFIX)/bin
ETC=$(PREFIX)/etc
VAR=$(PREFIX)/var
CACHE=$(VAR)/cache
PID=$(VAR)/run

CXX=g++
DEBUG= -g #-D_DEBUG #-fprofile-arcs -ftest-coverage # -pg -g
LINT=-Wshadow -Wall # -W -Wconversion -Wwrite-strings -Wunused
CXXFLAGS+=-O3 -g3 -ggdb -march=native -mtune=native -DVERSION=\"${VERSION}\" $(LINT) $(DEBUG) -DCONFIG=\"${ETC}/entropybroker.conf\" -DCACHE_DIR=\"${CACHE}\" -DPID_DIR=\"${PID}\"
LDFLAGS+=$(DEBUG) -lcrypto -lrt -lz -lutil

OBJSeb=pools.o handle_client.o config.o error.o fips140.o kernel_prng_rw.o log.o protocol.o main.o math.o pool.o scc.o signals.o utils.o auth.o my_pty.o ivec.o
OBJSsa=server_audio.o error.o utils.o kernel_prng_rw.o log.o protocol.o server_utils.o auth.o my_pty.o
OBJSst=server_timers.o log.o utils.o error.o kernel_prng_rw.o protocol.o server_utils.o auth.o my_pty.o
OBJSsv=server_v4l.o error.o log.o protocol.o kernel_prng_rw.o utils.o server_utils.o auth.o my_pty.o
OBJSss=server_stream.o error.o log.o protocol.o kernel_prng_rw.o utils.o server_utils.o auth.o my_pty.o
OBJSse=server_egd.o error.o log.o kernel_prng_rw.o protocol.o utils.o server_utils.o auth.o my_pty.o
OBJSclk=client_linux_kernel.o error.o kernel_prng_io.o kernel_prng_rw.o log.o protocol.o utils.o auth.o my_pty.o
OBJScle=client_egd.o error.o log.o kernel_prng_io.o kernel_prng_rw.o math.o protocol.o utils.o auth.o my_pty.o
OBJSte=test_egd_speed.o utils.o kernel_prng_rw.o log.o error.o auth.o my_pty.o
OBJSsk=server_linux_kernel.o utils.o kernel_prng_rw.o kernel_prng_io.o log.o error.o protocol.o server_utils.o auth.o my_pty.o
OBJScf=client_file.o error.o log.o kernel_prng_io.o kernel_prng_rw.o math.o protocol.o utils.o auth.o my_pty.o
OBJSpf=server_push_file.o utils.o kernel_prng_rw.o kernel_prng_io.o log.o error.o protocol.o server_utils.o auth.o my_pty.o
OBJSep=server_ext_proc.o utils.o kernel_prng_rw.o kernel_prng_io.o log.o error.o protocol.o server_utils.o auth.o my_pty.o
OBJSsu=server_usb.o utils.o kernel_prng_rw.o kernel_prng_io.o log.o error.o protocol.o server_utils.o auth.o my_pty.o

all:
	echo targets:
	echo -------
	echo All targets (except from 'plot') require the OpenSSL libraries.
	echo
	echo entropy_broker          - main daemon which distributes the entropy data
	echo
	echo eb_server_audio         - retrieves noise from an audio device
	echo	requires libasound2-dev, linux only
	echo
	echo eb_server_timers        - retrieves entropy by comparing jitter of timers
	echo
	echo eb_server_v4l           - retrieves noise from video4linux2 devices (webcams etc)
	echo	linux only
	echo
	echo eb_server_stream        - retrieves entropy data from a serial port or a hardware rng
	echo
	echo eb_server_egd           - retrieves entropy data from an EGD services (e.g. entropykey)
	echo
	echo eb_server_push_file
	echo
	echo eb_server_ext_proc
	echo
	echo eb_server_usb
	echo	requires libusb-1.0-0-dev
	echo
	echo eb_server_linux_kernel  - retrieves(!) entropy data from a /dev/random device
	echo	linux only
	echo
	echo eb_client_linux_kernel  - sends(!) entropy data to a linux kernel
	echo	linux only
	echo
	echo eb_client_file
	echo
	echo eb_client_egd
	echo
	echo
	echo eb_test_egd_speed
	echo
	echo plot
	echo	requires libpng-dev
	echo
	echo use:
	echo	make everything
	echo to build all daemons
	echo use:
	echo	make install
	echo to install all daemons etc. under $(PREFIX)
	echo

everything: entropy_broker eb_server_audio eb_server_timers eb_server_v4l eb_server_stream eb_client_linux_kernel eb_server_egd eb_client_egd eb_test_egd_speed eb_server_linux_kernel eb_client_file eb_server_push_file eb_server_ext_proc eb_server_usb

check:
	cppcheck -v --enable=all --std=c++11 --inconclusive . 2> err.txt

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

eb_test_egd_speed: $(OBJSte)
	$(CXX) $(LINT) $(OBJSte) $(LDFLAGS) -o eb_test_egd_speed

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

plot: plot.o
	$(CXX) $(LINT) plot.o $(LDFLAGS) -lpng -o plot

install: entropy_broker eb_server_audio eb_server_timers eb_server_v4l eb_server_stream eb_server_egd eb_client_linux_kernel eb_client_egd eb_test_egd_speed eb_server_linux_kernel eb_client_file eb_server_push_file eb_server_ext_proc eb_server_usb plot
	mkdir -p $(BIN) $(ETC) $(VAR) $(PID) $(CACHE)
	cp entropy_broker $(BIN)
	cp eb_server_audio $(BIN)
	cp eb_server_timers $(BIN)
	cp eb_server_v4l $(BIN)
	cp eb_server_stream $(BIN)
	cp eb_server_egd $(BIN)
	cp eb_client_linux_kernel $(BIN)
	cp eb_client_egd $(BIN)
	cp eb_test_egd_speed $(BIN)
	cp eb_server_linux_kernel $(BIN)
	cp eb_client_file $(BIN)
	cp eb_server_push_file $(BIN)
	cp eb_server_ext_proc $(BIN)
	cp eb_server_usb $(BIN)
	cp entropybroker.conf $(ETC)
	cp password.txt $(ETC)
	chmod 600 $(ETC)/password.txt

clean:
	rm -f $(OBJSeb) $(OBJSsa) $(OBJSst) $(OBJSsv) $(OBJSss)$(OBJSse) $(OBJSclk) $(OBJSte) $(OBJSsk) $(OBJScf) $(OBJSpf) $(OBJSep) $(OBJSsu) entropy_broker core *.da *.gcov *.bb* *.o eb_server_audio eb_server_timers eb_server_v4l eb_server_stream eb_server_egd eb_client_linux_kernel eb_client_egd eb_test_egd_speed eb_server_linux_kernel eb_client_file eb_server_push_file eb_server_ext_proc eb_server_usb

package:
	mkdir eb-$(VERSION)
	cp *.cpp *.h entropybroker.conf Makefile Changes password.txt readme.txt license.* eb-$(VERSION)
	cp -a doc eb-$(VERSION)
	tar czf eb-$(VERSION).tgz eb-$(VERSION)
	rm -rf eb-$(VERSION)
