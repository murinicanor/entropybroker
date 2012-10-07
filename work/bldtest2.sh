#! /bin/sh

g++ -ggdb -lcrypto -lutil -pthread -lrt test2.cpp encrypt_stream*cpp error.cpp  log.cpp  utils.cpp kernel_prng_rw.cpp my_pty.cpp
