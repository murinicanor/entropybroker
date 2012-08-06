#! /usr/bin/perl -w

open(FILE, "<" . $ARGV[0]) or die 'Cannot open file '.$ARGV[0];
binmode(FILE); 

$buffer = '';
while(!eof(FILE))
{
	read(FILE, $buffer, 4096);

	foreach(split(//, $buffer))
	{
		printf("%d\n", ord($_));
	}
}

close(FILE);
