package org.example.bcpqc.experiments.hashing;

import java.util.Map;
import java.util.function.Supplier;

public class HashingProviderProvider {

    public static boolean EXECUTE_PARALLEL = false;
    private static final Map<String, Supplier<HashingProvider>> providers = Map.of(
            "bc", BCHashingProvider::new,
            "bc-optimized", BCOptimizedHashingProvider::new,
            "corretto", CorrettoHashingProvider::new,
            "jni", JNIHashingProvider::new,
            "jni-fixed-padding", JNIFixedPaddingHashingProvider::new,
            "jni-prf-cache", JNIPrfCachingHashingProvider::new,
            "java", JavaHashingProvider::new,
            "java-optimized", JavaOptimizedHashingProvider::new
    );
    private static HashingProvider hashingProvider = new JNIHashingProvider();

    public static HashingProvider getHashingProvider() {
        return hashingProvider;
    }

    public static void setHashingProvider(String name) {
        hashingProvider = providers.get(name).get();
    }
}
