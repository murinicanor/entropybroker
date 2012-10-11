#! /bin/sh

g++ -O3 -march=native -mtune=native -pthread -lcrypto++ testcp.cpp
