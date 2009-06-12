Building
--------
	make install
Files will be installed in  /usr/local/entropybroker .
You need the OpenSSL development libraries as wel as the asound2
development libraries (asound2 is only required if you're
compiling server_audio).

On the server, invoke 'eb' (/usr/local/entropybroker/bin/eb).
On the clients, start client_linux_kernel (as root user).
On systems with a spare sound-card, start server_audio.
On systems with a spare tv-card/webcam, start server_v4l.
On systems that are mostly idle, start server_timers.

Please invoke these commands first with -h to see a list of
options. You probably need to use '-i' to select the server
on which 'eb' runs. Also adding '-s' is usefull as it'll make
the servers/clients/eb log to syslog.

It uses port 55225 (TCP) for communication.


--- folkert@vanheusden.com
