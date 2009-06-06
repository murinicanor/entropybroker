VERSION=0.1

DEBUG= -g #-D_DEBUG #-fprofile-arcs -ftest-coverage # -pg -g
CFLAGS+=-O2 -DVERSION=\"${VERSION}\" $(DEBUG)
LDFLAGS+=$(DEBUG) -lstdc++ -lcrypto -lssl

OBJS=error.o handle_pool.o kernel_prng_io.o main.o math.o pool.o utils.o

all: eb

eb: $(OBJS)
	$(CC) -Wall -W $(OBJS) $(LDFLAGS) -o eb

install: eb
	cp eb /usr/local/sbin

clean:
	rm -f $(OBJS) eb core *.da *.gcov *.bb*

package: clean
	mkdir eb-$(VERSION)
	cp *.cpp *.h Makefile Changes readme.txt license.txt todo eb-$(VERSION)
	tar czf eb-$(VERSION).tgz eb-$(VERSION)
	rm -rf eb-$(VERSION)
