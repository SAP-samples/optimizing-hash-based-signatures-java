package com.sap.pq_sig_benchmark.wots.wotsplusc;

import org.openjdk.jmh.annotations.*;

import java.util.concurrent.TimeUnit;

@State(Scope.Thread)
@Measurement(iterations = (1 << 10), time = 1, timeUnit = TimeUnit.MICROSECONDS)
@Warmup(iterations = 128, time = 1, timeUnit = TimeUnit.MICROSECONDS)
public class WOTSPlusCBenchmarkW16_2e10 extends WOTSPlusCBenchmark {
    @Param("16")
    int winternitzParameter;

    @Param({"480", "490", "500", "510", "520", "530", "540", "550", "560", "570", "580", "590", "600", "610", "620", "630", "640", "650", "660", "670"})
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
        return 128;
    }
}
