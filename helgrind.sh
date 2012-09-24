#! /bin/sh

valgrind --tool=helgrind ./entropy_broker -c ./entropy_broker.conf -n -l err.log 2> err8.log
