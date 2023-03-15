# JNI interface for Hash-Based Signatures

This package makes multiple native hash function implementations available to Java programs. It is tailored for use with
the ``bcpqc`` project and provides functionality specific to the XMSS, LMS, and SPHINCS+ hash-based signature scheme.

It supports the following hash algorithms:

- SHA256: Uses OpenSSL. Accessible via class ``JniHash``.
- SHAKE256: Uses XKCP. Accessible via class ``JniShake``
- Haraka: Implementations for Haraka256, Haraka512, and HarakaS based on the ``JavaSpincsPlus`` project (see below). Also contains software implementations for these algorithms (classes ending in ``Soft``).

Depending on hash algorithm and signature scheme, additional optimizations are available, e.g. PRF Caching for XMSS with SHA256_256.

## Thrid-Party Code

This repository incorporates and modifies code from the ``JavaSpincsPlus`` project by Lene Heimberger, published under MIT license. https://extgit.iaik.tugraz.at/krypto/javasphincsplus.
This code is in the ``org.example.jnihash.haraka`` java package and the folder ``src/native/src/haraka``.

Furthermore, it includes the FIPS202 (Keccak/SHAKE256) implementation used in the XMSS reference implementation by
Andreas Hülsing and Joost Rijneveld, available under the CC0 1.0 Universal Public Domain Dedication. https://github.com/XMSS/xmss-reference.
This code is in the folder ``src/native/src/custom_fips202``.

## Dependencies
### XKCP

XKCP provides optimized implementations of Keccak including SHAKE256.

1. Clone from https://github.com/XKCP/XKCP into parent directory
2. Modify `Makefile.build` to add compiler flag to allow static linking:

        <!-- To make a library -->
        <fragment name="libXKCP.a" inherits="All">
            <gcc>-fPIC</gcc>
        </fragment>
        <fragment name="libXKCP.so" inherits="All"/>

3. Compile:
    - For AVX2: ``make AVX2/libXKCP.a``
    - For AVX512 (prefer if available): ``make AVX512/libXKCP.a``. Move result: ``cp -r bin/AVX512/ bin/AVX2/``

### OpenSSL

OpenSSL's SHA256 implementation is used by this project. Generally, we do not require a certain version of OpenSSL.
However, we use legacy APIs in OpenSSL. Though they are still supported in OpenSSL 3.0 and later, we observe worse
performance with OpenSSL 3.0. Hence, we strongly suggest using OpenSSL 1.1.1.

## Build

    Generate Headers (might require mvn clean and deleting old headers):
    $ mvn compile

    Compile and link shared library:
    $ mvn native:compile
    $ mvn native:link

    Install
    $ mvn install


Currently, the resulting `libnative.so` must be made available to depending projects by setting the library path to this
project (or a copy of the file). This can be achieved with the flag ``-Djava.library.path=./target``.

Alternatively, the library can be copied into the system-wide default library path:

    sudo mkdir -p /usr/java/packages/lib
    sudo cp target/libnative.so /usr/java/packages/lib


Unpacking from a jar on runtime seems to be the only way to bundle the library in a jar. This was not done for the sake of performance and simplicity.

## Benchmark

We provide a benchmark for various hash implementations in ``src/native/src/benchmark.c``. It can be compiled using the
script ``make_benchmark.sh``.