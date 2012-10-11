#! /bin/sh

# SVN: $Revision$

valgrind --tool=helgrind --main-stacksize=16777216 --read-var-info=yes --free-is-write=yes ./entropy_broker -c ./entropy_broker.conf -n -l err.log -L 255 2> err8.log
