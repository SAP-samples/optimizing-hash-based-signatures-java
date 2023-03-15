# Post-Quantum Signature Benchmark

This project provides benchmarking capabilities for the hash-based signature schemes in ``bcpqc``. It uses the Java
Microbenchmark Harness (JMH) as a framework.

## Benchmarks
It contains the following benchmark types:

### HashBenchmark (com.sap.pq_sig_benchmark.hash)

Contains benchmarks for hash functions and corresponding input sizes for XMSS and SHPINCS+. Benchmarks the underlying 
hash implementation.

### KeyGenerationBenchmark (com.sap.pq_sig_benchmark.keygen)

Benchmarks the key generation for XMSS, XMSS^MT, LMS, and SPHINCS+

### SignatureBenchmark (com.sap.pq_sig_benchmark.sign)

Benchmarks the signature for XMSS, XMSS^MT, LMS, and SPHINCS+. It always signs the same message while the key's state is only 
reset with each new JMH iteration (i.e. *not* for each invocation of the sign operation). For all schemes except LMS, 
keys are loaded from the ``keys/`` folder (or generated and saved, if no key pair is available for this parameter set). 
For LMS, a new key pair is generated for each JMH iteration (without serialization).

The ``StateSizeBenchmarkRunner`` can be used to test way the size of the state changes over a key's lifetime.

### VerificationBenchmark (com.sap.pq_sig_benchmark.verify)

Benchmarks the signature verification for XMSS, XMSS^MT, LMS, and SPHINCS+. Creates a new signature for the same message
for each JMH iteration.

### Winternitz Tuning (com.sap.pq_sig_benchmark.wots)

Benchmarks for WOTS-BR and WOTS+C. The ``IterationBenchmarks`` are intended to measure the duration of one
iteration of both schemes, i.e. how long it takes to test one counter. ``WOTSPlusCBenchmark`` and ``WOTSBRBenchmark`` 
measure both the runtime as well as the achieved results for both schemes. For each JMH iteration, a different message
is signed. Messages are equal for each parameter set. JMH iteration times are chosen to ensure that each JMH iteration 
invokes the WOTS signing only once.

The benchmarks are split into multiple classes to allow for different JMH iteration counts depending on the chosen 
parameter for WOTS+C/-BR.

## Results

Raw results of our benchmark runs are available in the ``doc/`` folder. These also contain the corresponding commands 
that were used to run the benchmarks.

Benchmarks were executed on AWS on instance types ``m5zn`` and ``m6i``. Hyper-Threading was disabled in the AWS CPU options.
For single-threaded workloads, we used the ``xlarge`` size (2 cores, 2 threads w/o HT). For parallelized workloads, we 
used the ``2xlarge`` instance size (4 cores, 4 threads w/o HT).