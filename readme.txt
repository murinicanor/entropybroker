How it works
------------
The 'eb' process is the central process of it all. It collects all
entropy data, mixes it within its pool(s), measures the amount of
randomness in that data en then serves it to clients.
server_* processes, which can run in other systems than the eb-
process, collect the random-data and transmit that to the central
eb-process.
client_* processes, which also can run everywhere, get random-data
from the central eb-process and feed that to for example the local
linux-kernel (/dev/random so to say) or to processes that read
from a egb-compatible unix-domain socket.
If that eb-process is on a different system than the server_- or
client_- processes, then you're advised to let that communication
proceed over a network seperate from production-lan, unless no-
one can intercept the communication.

Building
--------
	make install
Files will be installed in  /usr/local/entropybroker .
You need the OpenSSL development libraries as wel as the asound2
development libraries (asound2 is only required if you're
compiling server_audio).

On the server, invoke 'eb' (/usr/local/entropybroker/bin/eb).

On systems with a spare sound-card, start server_audio.
On systems with a spare tv-card/webcam, start server_v4l.
On systems that are mostly idle, start server_timers. Check http://vanheusden.com/te/#bps to see some expected bitrates.
On systems with an random generator connected to e.g. a serial port, or with a rng in the motherboard chipset, use server_stream to feed its data to eb.
On systems with an EntropyKey (http://www.entropykey.co.uk/) or EGD, start server_egd.
server_egd requires a read-interval and how many bytes to read in
that interval. You can test with test_egd_speed how many bytes your
EGD service can produce in an interval.

On the clients, start client_linux_kernel (as root user)
or if you do not want the entropy data be send to /dev/random but
exported as a EGD server, start client_egd. Yes, the name may be
confusing but it is a client of the entropybroker-server. E.g.
client_egd -d /tmp/egd.sock -i eb-server.test.com
Now egd-clients can use the /tmp/egd.sock unix domain socket. This
should work with at least OpenSSL: then, start client_egd with
one of the following parameters:
 -d /var/run/egd-pool or -d /dev/egd-pool or -d /etc/egd-pool or
 -d /etc/entropy
To verify that client_egd functions, run:
  openssl rand -rand /var/run/egd-pool -out /tmp/bla 10
It should return something like
  255 semi-random bytes loaded
where '255' should be > 0. If it is zero, check if the current
user has enough rights to access /var/run/egd-pool

If you want the kernel buffers to be filled much earlier (the default
is when it only has 128 bits left), then write a new value to:
/proc/sys/kernel/random/write_wakeup_threshold
E.g.:
	echo 512 > /proc/sys/kernel/random/write_wakeup_threshold

If one of the server processes quits after a while (or even
immediately), then check its logging to see what the problem is. All
processes have the following command-line switches for that:
-s       log to syslog
-l file  log to a file
-n       do not fork: messages will appear in your terminal

Please invoke these commands first with -h to see a list of
options. You probably need to use '-i' to select the server
on which 'eb' runs. Also adding '-s' is usefull as it'll make
the servers/clients/eb log to syslog.

It uses port 55225 (TCP) for communication.

Send a HUP signal to the eb-daemon to let it log the current
state. E.g. recv/sent requests, etc.


License: GPL2

--- folkert@vanheusden.com
