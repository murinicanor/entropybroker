#! /bin/sh

# SVN: $Revision$

valgrind --tool=helgrind ./entropy_broker -c ./entropy_broker.conf -n -l err.log 2> err8.log
