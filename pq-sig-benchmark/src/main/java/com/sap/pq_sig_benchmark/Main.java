package com.sap.pq_sig_benchmark;

import com.sap.pq_sig_benchmark.keygen.LMSKeyGenerationBenchmark;
import com.sap.pq_sig_benchmark.keygen.SPHINCSPlusKeyGenerationBenchmark;
import com.sap.pq_sig_benchmark.sign.SPHINCSPlusSignatureBenchmark;
import com.sap.pq_sig_benchmark.verify.SPHINCSPlusVerificationBenchmark;
import com.sap.pq_sig_benchmark.verify.XMSSVerificationBenchmark;
import com.sap.pq_sig_benchmark.wots.wotsbr.WOTSBRBenchmark;
import com.sap.pq_sig_benchmark.wots.wotsplusc.WOTSPlusCBenchmark;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import org.openjdk.jmh.runner.options.TimeValue;

@SuppressWarnings("unused")
public class Main {

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder().include(SPHINCSPlusVerificationBenchmark.class.getSimpleName())
                //.include(WOTSBRIterationBenchmark.class.getSimpleName())
                //.include(CorrettoProviderHashBenchmark.class.getSimpleName())
                //.include(XMSSKeyGenerationBenchmark.class.getSimpleName())
                .forks(1)
                //.resultFormat(ResultFormatType.CSV)
                .warmupIterations(0)
                .measurementIterations(1)
                .warmupTime(TimeValue.seconds(30))
                .measurementTime(TimeValue.seconds(1))
                //.param("zzz_parallel", "true")
                .param("digestName", /*"SHA-256",*/ "SHA-256")
                //.param("robust", "false")
                .param("paramSize", /*"16",*/ /*"24",*/ "32")
                .param("lms_sig_parameter", Parameters.LMS_SIG_SHA256_M32_H5/*, Parameters.LMS_SIG_SHA256_M24_H15, Parameters.LMS_SIG_SHAKE_M32_H10, Parameters.LMS_SIG_SHAKE_M32_H15*/)
                //.param("xmssmt_parameter", Parameters.XMSSMT_SHA2_20d2_192, Parameters.XMSSMT_SHA2_20d4_192, Parameters.XMSSMT_SHA2_40d4_192, Parameters.XMSSMT_SHA2_40d8_192)
                //.param("xmss_parameter", "SHA2_10_256", "SHAKE_10_256", "SHA2_10_512", "SHAKE_10_512", "SHA2_16_256", "SHAKE_16_256", "SHA2_16_512", "SHAKE_16_512")
                .param("xmss_parameter", "SHA2_10_192"/*, "SHA2_16_256" /* "SHA2_10_192", "SHAKE256_10_256", "SHAKE256_10_192"*/)
                .param("sphincsplus_parameter", "sha2_128s", "sha2_192s", "sha2_256s", "shake_192s", "shake_256s", "haraka_192s", "haraka_256s", "sha2_128f", "sha2_192f", "sha2_256f", "sha2_128s_simple", "sha2_192s_simple", "sha2_256s_simple", "shake_192s_simple", "shake_256s_simple", "haraka_192s_simple", "haraka_256s_simple", "sha2_128f_simple", "sha2_192f_simple", "sha2_256f_simple")
                //.param("sphincsplus_parameter", "sha2_128s", "sha2_192s", "sha2_256s" , "shake_128s", "shake_192s", "shake_256s", "haraka_128s", "haraka_192s", "haraka_256s", "sha2_128f", "sha2_192f", "sha2_256s" , "shake_128f", "shake_192f", "shake_256f", "haraka_128f", "haraka_192f", "haraka_256f")
                //.param("sphincsplus_parameter", "shake_192s")
                //.param("hashingProvider", "java", "java-optimized")
                .param("hashingProvider", "bc", "jni", "java"/*, "bc", "java" "jni", "jni-fixed-padding", "jni-prf-cache"*/)
                .param("includeChecksum", "false")
                .param("useOnePadding", "false")
                .build();
        new Runner(opt).run();
    }

}
