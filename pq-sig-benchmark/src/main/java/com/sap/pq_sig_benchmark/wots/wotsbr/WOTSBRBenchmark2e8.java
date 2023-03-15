package com.sap.pq_sig_benchmark.wots.wotsbr;

import org.openjdk.jmh.annotations.*;

import java.util.concurrent.TimeUnit;

@State(Scope.Thread)
@Measurement(iterations = (1 << 8), time = 1, timeUnit = TimeUnit.MICROSECONDS)
@Warmup(iterations = 32, time = 1, timeUnit = TimeUnit.MICROSECONDS)
public class WOTSBRBenchmark2e8 extends WOTSBRBenchmark {
    @Param({"28"})
    int wotsBrIterationsLog2;

    @Override
    int getWotsBrIterations() {
        return 1 << wotsBrIterationsLog2;
    }

    @Override
    int getWarmupIterations() {
        return 32;
    }
}
