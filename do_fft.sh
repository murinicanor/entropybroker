#! /bin/sh
# SVN: $Revision$

if [ $# -eq 0 ] ; then
	echo usage: do_fft.sh bin_file.dat result.png
	echo this script requires gnuplot, confft and bin_to_values.pl in the same path
	exit 1
fi

TEMP1=/tmp/__random__$$.dat
TEMP2=/tmp/__random__$$.fft

./bin_to_values.pl $1 > $TEMP1

(echo 0 ; confft -f $TEMP1 -m | tail -n +2) > $TEMP2

rm $TEMP1

gnuplot <<EOF > $2
set term png size 800,600
set autoscale
set title "FFT of $1"
set xlabel "freq"
set ylabel "magnitude
plot "$TEMP2" using 1 with lines title 'magnitude'
EOF

rm $TEMP2
