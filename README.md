# Optimizing Hash-Based Signatures in Java

[![REUSE status](https://api.reuse.software/badge/github.com/SAP-samples/optimizing-hash-based-signatures-java)](https://api.reuse.software/info/github.com/SAP-samples/optimizing-hash-based-signatures-java)

**WARNING**: This project is intended for **evaluation purposes only** and **MUST NOT** be used in any productive environment.

## Description

This project explores and evaluates optimizations for the hash-based signature schemes XMSS, LMS, and SPHINCS+ in BouncyCastle. It integrates hardware acceleration and other software optimizations and provides benchmark tooling and results.

The project consists of the following subprojects:

### ``bcpqc``

Fork of BouncyCastle's implementation of XMSS, LMS, and SPHINCS+. Integrates parameter sets specified in NIST SP 800-208, optimized hash function implementations, parallelized hash tree traversal, and implementations of WOTS-BR and WOTS+C.

### ``pq-sig-benchmark``

Benchmarking tools for ``bcpqc``.

### ``jni-hash``

Provides access to native hash implementations via the Java Native Interface (JNI). Required for the JNI hashing providers in ``bcpqc``.

### ``jdk-patch``

A patch for OpenJDK 18 to allow direct access to the SHA256 implementation and implement intrinsics for Haraka.

### ``jni-transfer-benchmark``

A independent project to benchmark different strategies to pass data between Java and native code.

## Requirements

See individual subprojects.

## Download and Installation

See the individual repositories. In ``pq-sig-benchmark``, ``doc/aws-setup.md`` describes our benchmarking setup on AWS. This can be taken as a guideline on how to install all required parts.

## How to obtain support
[Create an issue](https://github.com/SAP-samples/<repository-name>/issues) in this repository if you find a bug or have questions about the content.
 
## Contributing
If you wish to contribute code, offer fixes or improvements, please send a pull request. Due to legal reasons, contributors will be asked to accept a DCO when they create the first pull request to this project. This happens in an automated fashion during the submission process. SAP uses [the standard DCO text of the Linux Foundation](https://developercertificate.org/).

## License
Copyright (c) 2023 SAP SE or an SAP affiliate company. All rights reserved. This project is licensed under the Apache Software License, version 2.0 except as noted otherwise in the [LICENSE](LICENSE) file.

