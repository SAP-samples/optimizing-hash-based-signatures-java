package com.sap.pq_sig_benchmark.wots.wotsplusc;

import org.openjdk.jmh.annotations.*;

import java.util.concurrent.TimeUnit;

@State(Scope.Thread)
@Measurement(iterations = (1 << 10), time = 1, timeUnit = TimeUnit.MICROSECONDS)
@Warmup(iterations = 128, time = 1, timeUnit = TimeUnit.MICROSECONDS)
public class WOTSPlusCBenchmarkW4_2e10 extends WOTSPlusCBenchmark {
    @Param("4")
    int winternitzParameter;

    @Param({"192", "196", "200", "204", "208", "212", "216", "220", "224", "228", "232", "236", "240", "244", "248", "252", "256"})
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
