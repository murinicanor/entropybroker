#! /bin/sh

valgrind --tool=helgrind ./entropy_broker -c ./entropy_broker.conf -n 2> err8.log
