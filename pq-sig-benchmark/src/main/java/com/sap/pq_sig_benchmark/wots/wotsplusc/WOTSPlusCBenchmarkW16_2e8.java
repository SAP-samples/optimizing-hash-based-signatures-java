package com.sap.pq_sig_benchmark.wots.wotsplusc;

import org.openjdk.jmh.annotations.*;

import java.util.concurrent.TimeUnit;

@State(Scope.Thread)
@Measurement(iterations = (1 << 8), time = 1, timeUnit = TimeUnit.MICROSECONDS)
@Warmup(iterations = 32, time = 1, timeUnit = TimeUnit.MICROSECONDS)
public class WOTSPlusCBenchmarkW16_2e8 extends WOTSPlusCBenchmark {
    @Param("16")
    int winternitzParameter;

    @Param({"680", "686"})
    int wotsPlusCSum;

    @Override
    protected int getWinternitzParameter() {
        return winternitzParameter;
    }

    @Override
    int getWotsPlusCSum() {
        return wotsPlusCSum;
    }

    @Override
    int getWarmupIterations() {
        return 32;
    }
}
