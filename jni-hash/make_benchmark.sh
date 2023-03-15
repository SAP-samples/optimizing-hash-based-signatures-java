/usr/bin/gcc -lc -O3 -o target/benchmark src/native/src/benchmark.c src/native/src/sha256.c src/native/src/custom_fips202/fips202.c -lcrypto  -Isrc/native/src/ -I../XKCP/bin/AVX2/libXKCP.a.headers/ -L../XKCP/bin/AVX2/ -lXKCP 

# For profiling 
# /usr/bin/gcc -lc  -o target/benchmark_profile src/native/src/benchmark.c src/native/src/sha256.c  -Isrc/native/src/ -I../XKCP/bin/AVX2/libXKCP.a.headers/ -L../XKCP/bin/AVX2/ -lXKCP -g  -L../openssl-1.1.1q -l:libcrypto.a -ldl  -lpthread -pg
# https://stackoverflow.com/a/25811538