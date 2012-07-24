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
	echo 512 > cat /proc/sys/kernel/random/write_wakeup_threshold

Please invoke these commands first with -h to see a list of
options. You probably need to use '-i' to select the server
on which 'eb' runs. Also adding '-s' is usefull as it'll make
the servers/clients/eb log to syslog.

It uses port 55225 (TCP) for communication.

Send a HUP signal to the eb-daemon to let it log the current
state. E.g. recv/sent requests, etc.


License: GPL2

--- folkert@vanheusden.com
