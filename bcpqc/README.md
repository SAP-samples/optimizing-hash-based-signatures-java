# Optimized Hash-Based Signatures in BouncyCastle

**WARNING**: This fork is intended for evaluation purposes only and **MUST NOT** be used in any productive environment.

This is a partial fork of BouncyCastle containing implementations for the following hash-based signature schemes:

- XMSS (and its hypertree version XMSS^MT)
- LMS
- SPHICS+

Major changes of this fork:

- Integration of the parameter sets specified by NIST in SP 800-208 for XMSS/XMSS^MT and LMS
- All hash operations extracted into abstract interfaces to allow different hash function implementations (
  see ``HashingProvider``)
- Integration of multiple hash implementations (see below)
- Parallelized implementation of XMSS, LMS, and SPHINCS+ key generation as well as SPHINCS+ signing. (For SPHINCS+, this
  fork only parallelizes the Merkle tree traversal used in both key generation and signing)
- Implementations for WOTS-BR and WOTS+C based on the WOTS implementation used in XMSS

## Hash function implementations

| Name                  | Provider                           | XMSS            | LMS         | SPHINCS+ | Description                                                                                                                                                                                                    |
|-----------------------|------------------------------------|-----------------|-------------|----------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| ``bc``                | ``BCHashingProvider``              | yes             | yes         | yes      | Default hash implementation used by BouncyCastle                                                                                                                                                               |
| ``bc-optimized``      | ``BCOptimizedHashingProvider``     | only SHA256     | no          | no       | Avoids intermediate buffer in ``GeneralDigest``, applies PRF caching for ``n = 32``                                                                                                                            |
| ``corretto``          | ``CorrettoHashingProvider``        | only SHA256     | only SHA256 | no       | Uses the Amazon Corretto Crypto Provider [^1] for hashing (which uses OpenSSL via JNI)                                                                                                                         |
| ``jni``               | ``JNIHashingProvider``             | yes             | yes         | yes      | OpenSSL, XKCP and a custom Haraka implementation for native hashing using ``jni-hash``                                                                                                                         |
| ``jni-fixed-padding`` | ``JNIFixedPaddingHashingProvider`` | only SHA256     | only SHA256 | no       | Applies a hard-coded padding for the SHA2 input data [^1]. Reduces indirections in OpenSSL.                                                                                                                    |
| ``jni-prf-caching``   | ``JNIPrfCachingHashingProvider``   | only SHA256_256 | no          | no       | Additionally uses PRF caching [^1]                                                                                                                                                                             |
| ``java``              | ``JavaHashingProvider``            | only SHA256     | only SHA256 | yes      | Uses the default Java ``MessageDigest`` for XMSS/LMS. For SPHINCS+, it directly uses the underlying implementation class. For SPHINCS+, it uses a custom intrinsic implemented in the modified JDK (see below) |
| ``java-optmized``     | ``JavaOptimizedHashingProvider``   | only SHA256     | only SHA256 | no       | Directly uses the SHA256 compression function provided in ``sun.security.provider.SHA2$SHA256``. For XMSS SHA256_256, it additionally implements PRF caching                                                   |

## Configuration

The hash function implementation can be chosen by setting the static field ``hashingProvider`` in
class ``HashingProviderProvider``.
Parallel execution of the operations listed above can be enabled and disabled by setting ``EXECUTE_PARALLEL``
accordingly.

## Dependencies

- ``jni-hash``: For all hashing implementations starting with ``jni-``
- Patched OpenJDK: for all ``java-`` implementations

For instructions on how to install, please refer to the respective project.

## Installation

The project can be installed by running

    mvn install

This will download external dependencies, compile the source code, build a `.jar`-file and install this into the local
maven repository. To use this in another project, add the following dependency to the project's `pom.xml`:

        <dependency>
            <groupId>org.example</groupId>
            <artifactId>bcpqc</artifactId>
            <version>1.0-SNAPSHOT</version>
        </dependency>

## Usage

This fork renames the two relevant JCA/JCE providers because JCA refers to providers by using their name as a string.
Renaming avoids ambiguity.

- `SAPBouncyCastleProvider`: Forks the general ``BouncyCastleProvider``
- `SAPBouncyCastlePQCProvider`: Forks the post-quantum-specific ``BouncyCastlePQCProvider``

All forked classes are in the package `org.example.bcpqc`. They correspond to the classes with same name (and subpath)
in `org.bouncycastle`. If your IDE shows you two options for importing the class that is needed, always use the one in
`org.example.bcpqc` (i.e. prefer the fork over the original version of the class)

## References

[^1]: https://github.com/corretto/amazon-corretto-crypto-provider

[^2]: https://eprint.iacr.org/2018/1225
