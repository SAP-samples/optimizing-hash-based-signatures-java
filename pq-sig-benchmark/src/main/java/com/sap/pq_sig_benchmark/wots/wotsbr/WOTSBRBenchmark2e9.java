package com.sap.pq_sig_benchmark.wots.wotsbr;

import org.openjdk.jmh.annotations.*;

import java.util.concurrent.TimeUnit;

@State(Scope.Thread)
@Measurement(iterations = (1 << 9), time = 1, timeUnit = TimeUnit.MICROSECONDS)
@Warmup(iterations = 64, time = 1, timeUnit = TimeUnit.MICROSECONDS)
public class WOTSBRBenchmark2e9 extends WOTSBRBenchmark {
    @Param({"27"})
    int wotsBrIterationsLog2;

    @Override
    int getWotsBrIterations() {
        return 1 << wotsBrIterationsLog2;
    }

    @Override
    int getWarmupIterations() {
        return 64;
    }
}
