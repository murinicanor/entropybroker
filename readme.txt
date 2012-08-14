How it works
------------
The 'entropy_broker' process is the central process of it all. It
collects all entropy data, mixes it within its pool(s), measures
the amount of randomness in that data en then serves it to clients.

server_* processes, which can run in other systems than the
entropy_broker-process, collect the random-data and transmit that
to the central entropy_broker-process.

client_* processes, which also can run everywhere, get random-data
from the central entropy_broker-process and feed that to for
example the local linux-kernel (/dev/random so to say) or to
processes that read from a egb-compatible unix-domain socket.

Most daemons should run on all UNIX systems. The ones that are
Linux-specific are markes as such.

Building
--------
	make install
Files will be installed in  /usr/local/entropybroker 
You need the OpenSSL and zlib development libraries.
asound2 is for eb_server_audio
libusb-1.0-0-dev is for eb_server_usb

*** PLEASE NOTE: since 1.0, 'eb' was renamed to 'entropy_broker' ***
*** also the other daemons were renamed ***
*** ALSO: the network protocol has changed so it is no longer ***
*** compatible with older versions (1.1 is also incompatible ***
*** with 1.0) ***
*** LAST NOTE: the configuration file changed, see example ***


Usage
-----
Since version 1.0 all entropy-data is encrypted before it is
transmitted over the network.

Also, clients and servers need to authenticate before they can
talk to the entropybroker. For that you need to add a line
to entropybroker.conf like this:
	password = my-password.txt

Then 'my-password.txt' should contain the password you want to
use. Also the file should only be readable by the user under
which the entropy-broker and/or servers/clients run.
E.g. use chmod 600 my-password.txt

The client/server processes don't have a configuration file. For
them, you need to use '-X', e.g.:
	eb_server_v4l -X my-password.txt

Passwords should not be longer than 56 characters. If a binary
password is used, note that it is cut-off at the first LF (\n)
found.


server processes
================
On the server, invoke 'entropy_broker' (/usr/local/entropybroker/bin/entropy_broker).
Send a HUP signal to the entropy_broker-daemon to let it log the
current state. E.g. recv/sent requests, etc.
The main entropy broker process listens by default on port
55225 (TCP).

On systems with a spare sound-card, start server_audio. This requires a
functioning ALSA audio sub-system. Look in /proc/asound/devices for the
parameters. For example:
	mauer:/usr/local/entropybroker/var/log# cat /proc/asound/devices 
	  1:        : sequencer
	  2: [ 0- 1]: digital audio playback
	  3: [ 0- 0]: digital audio playback
	  4: [ 0- 0]: digital audio capture
	  5: [ 0- 2]: hardware dependent
	  6: [ 0]   : control
	  7: [ 1- 3]: digital audio playback
	  8: [ 1- 0]: hardware dependent
	  9: [ 1]   : control
	 10: [ 2- 0]: digital audio capture
	 11: [ 2]   : control
	 33:        : timer
In this example there are 3 audio cards (0, 1 and 2, see first column
between [ and ]). If we want to take the audio from card 2 (see line 10)
it would look like this:
eb_server_audio -d hw:2,0 -s -i broker -X 
This program is Linux-only (due to the ALSA requirement).
This program should work with the Johnson Noise 1* produced by the
electronic parts of the sound-card. So it is best, maybe not obvious,
to turn the volume as low as possible.
1* http://en.wikipedia.org/wiki/Johnson%E2%80%93Nyquist_noise

On systems with a spare tv-card/webcam, start server_v4l. E.g.:
eb_server_v4l -i broker -d /dev/video0 -s -X password.txt
This program is Linux-only (due to the video4linux2 requirement).
The same note regarding Johnson Noise (see the audio driver) applies
to this program. On the other hand: LavaRnd (http://www.lavarnd.org/)
works by the principle that what the camera "sees" is moving in a
random way. So either put e.g. a lava-lamp or fishtank in front of
the camera, or tune the tuner of the tv-card to a channel with
only noise or put a cap in front of the lense.

On systems that are mostly idle, start server_timers. Check
http://vanheusden.com/te/#bps to see some expected bitrates.
eb_server_timers -i broker -s -X password.txt
This program compares timers. Due to jitter in their frequency, noise
can be measured.

On systems with an random generator connected to e.g. a serial
port, or with a rng in the motherboard chipset, use server_stream
to feed its data to entropy_broker. For example a rng in the system
would be used like this:
eb_server_stream -i entropy_broker -d /dev/hwrng -s -X password.txt

On systems with an EntropyKey (http://www.entropykey.co.uk/) or
EGD, start server_egd.
server_egd requires a read-interval and how many bytes to read in
that interval. You can test with test_egd_speed how many bytes your
EGD service can produce in an interval. E.g.:
eb_server_egd -i broker -d /tmp/egd.socket.ekey -a 1024 -b 5 -X password.txt
This would require the following:
	EGDUnixSocket "/tmp/egd.socket.ekey
in the entropy-key daemons configuration (which is
/etc/entropykey/ekeyd.conf on Debian systems).

On systems with a RNG in the chipset that automatically gets send
to the linux kernel entropy buffer, use server_linux_kernel.
This program is Linux-only.

On systems with one or more USB devices attached (can be simple as
a keyboard or a mouse) you can use server_usb. This needs to run
with root access.
This program measures the response time of a device. This program
can be compared to server_timers as it measures the difference
between the clock of the pc and the clock in the usb device.

On systems without any hardware available for retrieving data, one
can, as a last resort, using eb_server_ext_proc. This command can
execute any command (as long as it is supported by the shell) and
feed its output to the broker. E.g.:
eb_server_ext_proc -i localhost -c '(find /proc -type f -print0 | xargs -0 cat ; ps auwx ; sensors -u) | gzip -9' -n -X password.txt

The server daemons that obtain data from hardware sources use
von neumann software whitening.
See: http://en.wikipedia.org/wiki/Hardware_random_number_generator#Software_whitening

If you have a large amount of entropy data available in a file
on disk, you can use server_file. Please note that you can use
the data only once.


client processes
================
To keep the entropy buffer of the local linux kernel filled-up, start
client_linux_kernel as a root user.
If you want the kernel buffers to be filled much earlier (the default
is when it only has 128 bits left), then write a new value to:
/proc/sys/kernel/random/write_wakeup_threshold
E.g.:
	echo 512 > /proc/sys/kernel/random/write_wakeup_threshold
This program is Linux-only.

eb_client_kernel_generic is for other systems like for example 
freebsd and macos x. For it to work, the /dev/random device needs to
accept data written to it. This should be the case for *bsd. The
program accepts a parameter indicating the number of bytes to write
and the number of seconds to sleep between each write.

To server entropy data like as if it was an EGD-server, start
client_egd. E.g.:
	eb_client_egd -d /tmp/egd.sock -i entropy_broker-server.test.com
You may need to delete the socket before starting eb_client_egd.
Now egd-clients can use the /tmp/egd.sock unix domain socket. This
should work with at least OpenSSL: start client_egd with one of the
following parameters: -d /var/run/egd-pool or -d /dev/egd-pool or
-d /etc/egd-pool or -d /etc/entropy
To verify that client_egd functions, run:
  openssl rand -rand /var/run/egd-pool -out /tmp/bla 10
It should return something like
  255 semi-random bytes loaded
where '255' should be > 0. If it is zero, check if the current
user has enough rights to access /var/run/egd-pool


Problem resolving
=================
If one of the server processes quits after a while (or even
immediately), then check its logging to see what the problem is.
All processes have the following command-line switches for that:
-s       log to syslog
-l file  log to a file
-n       do not fork: messages will appear in your terminal

Please invoke these commands first with -h to see a list of
options. You probably need to use '-i' to select the server
on which 'entropy_broker' runs. Also adding '-s' is usefull as
it'll make the servers/clients/entropy_broker log to syslog.


Tips
====
When your system has enough entropy, you can decide to let all
OpenSSL applications use the kernel entropy driver. For that,
in /etc/ssl/openssl.cnf change the line with RANDFILE in it
to:
	RANDFILE = /dev/urandom


Evaluation Entropy Broker
=========================
Use client_file to write a couple of bytes to a file.
Then with dieharder:
	http://www.phy.duke.edu/~rgb/General/dieharder.php
and also with ent:
	http://www.fourmilab.ch/random/
you can do some analysis of the randomness of the data.

You can also convert that binary file to a text-file containing
values so that you can analyze it using e.g. confft.
Convert it using:
	./bin_to_values.pl my_bin_file.dat > my_text_file.txt
confft can be retrieved from:
	http://www.vanheusden.com/confft/
You can also directly plot the fft using the do_fft.sh script:
	./do_fft.sh test.dat test.png
This requires gnuplot and confft.

An other option is to do a pixel-plot of some data (the more
the better). Here, for each pixel 2 bytes are taken and then
used as an x and y coordinate. That pixel is then increased
by one. If the result looks like noise, then all is fine.
Patterns are an indication that something is wrong.
To build that binary, invoke:
	make plot
This requires libpng-dev.
To invoke:
	plot input_data.dat result.png


License
=======
GPL2

--- folkert@vanheusden.com / folkert.mobiel@gmail.com
