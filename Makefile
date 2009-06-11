VERSION=0.1

DEBUG= -g #-D_DEBUG #-fprofile-arcs -ftest-coverage # -pg -g
CXXFLAGS+=-O0 -DVERSION=\"${VERSION}\" $(DEBUG)
LDFLAGS+=$(DEBUG) -lstdc++ -lcrypto -lssl

OBJS=client.o error.o handle_pool.o kernel_prng_io.o log.o main.o math.o pool.o utils.o

all: eb

eb: $(OBJS)
	$(CC) -Wall -W $(OBJS) $(LDFLAGS) -o eb

server_audio:
	gcc -pedantic -Wall -lstdc++ -lasound -g  $(CXXFLAGS) -o server_audio server_audio.cpp error.cpp utils.cpp log.cpp kernel_prng_io.cpp protocol.cpp

server_timers:
	gcc $(CXXFLAGS) -lstdc++ -o server_timers server_timers.cpp log.cpp utils.cpp error.cpp kernel_prng_io.cpp protocol.cpp

client_linux_kernel:
	gcc -lstdc++ $(CXXFLAGS) -o client_linux_kernel client_linux_kernel.cpp error.cpp kernel_prng_io.cpp utils.cpp log.cpp math.cpp

install: eb
	cp eb /usr/local/sbin

clean:
	rm -f $(OBJS) eb core *.da *.gcov *.bb*

package: clean
	mkdir eb-$(VERSION)
	cp *.c* *.h Makefile Changes readme.txt license.txt todo eb-$(VERSION)
	tar czf eb-$(VERSION).tgz eb-$(VERSION)
	rm -rf eb-$(VERSION)
