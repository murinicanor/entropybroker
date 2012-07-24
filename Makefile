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
VERSION=0.9

PREFIX=/usr/local/entropybroker
BIN=$(PREFIX)/bin
ETC=$(PREFIX)/etc
VAR=$(PREFIX)/var

CXX=g++
DEBUG= -g #-D_DEBUG #-fprofile-arcs -ftest-coverage # -pg -g
CXXFLAGS+=-O3 -DVERSION=\"${VERSION}\" $(DEBUG) -Wall -DCONFIG=\"${ETC}/entropybroker.conf\" -DCACHE=\"${VAR}/pools.dat\"
LDFLAGS+=$(DEBUG)

OBJSeb=handle_client.o config.o error.o fips140.o handle_pool.o kernel_prng_rw.o log.o main.o math.o pool.o scc.o signals.o utils.o
OBJSsa=server_audio.o error.o utils.o kernel_prng_rw.o log.o protocol.o server_utils.o
OBJSst=server_timers.o log.o utils.o error.o kernel_prng_rw.o protocol.o server_utils.o
OBJSsv=server_v4l.o error.o log.o protocol.o kernel_prng_rw.o utils.o server_utils.o
OBJSss=server_stream.o error.o log.o protocol.o kernel_prng_rw.o utils.o server_utils.o
OBJSse=server_egd.o error.o log.o kernel_prng_rw.o protocol.o utils.o server_utils.o
OBJSclk=client_linux_kernel.o error.o kernel_prng_io.o kernel_prng_rw.o log.o math.o protocol.o utils.o
OBJScle=client_egd.o error.o log.o kernel_prng_rw.o math.o protocol.o utils.o
OBJSte=test_egd_speed.o utils.o kernel_prng_rw.o error.o

all: eb server_audio server_timers server_v4l server_stream client_linux_kernel server_egd client_egd test_egd_speed

check:
	cppcheck -v --enable=all --std=c++11 --inconclusive . 2> err.txt

eb: $(OBJSeb)
	$(CXX) -Wall -W $(OBJSeb) $(LDFLAGS) -lcrypto -o eb

server_audio: $(OBJSsa)
	$(CXX) -Wall -W $(OBJSsa) $(LDFLAGS) -lasound -o server_audio

server_timers: $(OBJSst)
	$(CXX) -Wall -W $(OBJSst) $(LDFLAGS) -o server_timers

server_v4l: $(OBJSsv)
	$(CXX) -Wall -W $(OBJSsv) $(LDFLAGS) -o server_v4l

server_stream: $(OBJSss)
	$(CXX) -Wall -W $(OBJSss) $(LDFLAGS) -o server_stream

server_egd: $(OBJSse)
	$(CXX) -Wall -W $(OBJSse) $(LDFLAGS) -o server_egd

client_egd: $(OBJScle)
	$(CXX) -Wall -W $(OBJScle) $(LDFLAGS) -o client_egd

client_linux_kernel: $(OBJSclk)
	$(CXX) -Wall -W $(OBJSclk) $(LDFLAGS) -o client_linux_kernel

test_egd_speed: $(OBJSte)
	$(CXX) -Wall -W $(OBJSte) $(LDFLAGS) -o test_egd_speed

install: eb server_audio server_timers server_v4l server_stream server_egd client_linux_kernel client_egd test_egd_speed
	mkdir -p $(BIN) $(ETC) $(VAR)
	cp eb $(BIN)
	cp server_audio $(BIN)
	cp server_timers $(BIN)
	cp server_v4l $(BIN)
	cp server_stream $(BIN)
	cp server_egd $(BIN)
	cp client_linux_kernel $(BIN)
	cp client_egd $(BIN)
	cp test_egd_speed $(BIN)
	cp entropybroker.conf $(ETC)

clean:
	rm -f $(OBJSeb) $(OBJSsa) $(OBJSst) $(OBJSsv) $(OBJSss)$(OBJSse) $(OBJSclk) $(OBJSte) eb core *.da *.gcov *.bb* *.o server_audio server_timers server_v4l server_stream server_egd client_linux_kernel client_egd test_egd_speed

package: clean
	mkdir eb-$(VERSION)
	cp *.cpp *.h entropybroker.conf Makefile Changes readme.txt license.* eb-$(VERSION)
	tar czf eb-$(VERSION).tgz eb-$(VERSION)
	rm -rf eb-$(VERSION)
