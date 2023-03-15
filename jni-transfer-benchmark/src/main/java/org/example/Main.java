package org.example;

import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import org.openjdk.jmh.runner.options.TimeValue;

public class Main {
    public static void main(String[] args) throws RunnerException {
        System.load("/home/tim/jni-transfer-benchmark/target/libbenchmark.so");

        Options opt = new OptionsBuilder().include(JniTransferBenchmark.class.getSimpleName())
                .forks(1)
                // .resultFormat(ResultFormatType.CSV)
                .warmupIterations(2)
                .measurementIterations(5)
                .measurementTime(TimeValue.seconds(10))
                .build();
                
        new Runner(opt).run();
    }
}
