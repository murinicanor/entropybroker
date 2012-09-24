#! /bin/sh

valgrind --show-reachable=yes --leak-check=full --read-var-info=yes --track-origins=yes --malloc-fill=93 --free-fill=b9 --error-limit=no ./entropy_broker -c ./entropy_broker.conf -n 2> err8.log
