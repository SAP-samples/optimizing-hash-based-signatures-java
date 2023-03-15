package com.sap.pq_sig_benchmark.wots.wotsbr;

import org.openjdk.jmh.annotations.*;

import java.util.concurrent.TimeUnit;

@State(Scope.Thread)
@Measurement(iterations = (1 << 10), time = 1, timeUnit = TimeUnit.MICROSECONDS)
@Warmup(iterations = 128, time = 1, timeUnit = TimeUnit.MICROSECONDS)
public class WOTSBRBenchmark2e10 extends WOTSBRBenchmark {
    @Param({"10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26"})
    int wotsBrIterationsLog2;

    @Override
    int getWotsBrIterations() {
        return 1 << wotsBrIterationsLog2;
    }

    @Override
    int getWarmupIterations() {
        return 128;
    }
}
