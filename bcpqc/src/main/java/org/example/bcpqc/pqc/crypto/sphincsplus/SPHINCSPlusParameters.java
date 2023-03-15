package org.example.bcpqc.pqc.crypto.sphincsplus;

import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;
import org.example.bcpqc.experiments.hashing.HashingProviderProvider;

import java.util.HashMap;
import java.util.Map;

public class SPHINCSPlusParameters {
    public static final SPHINCSPlusParameters sha2_128f = new SPHINCSPlusParameters("sha2-128f-robust", new Sha2EngineProvider(true, 16, 16, 22, 6, 33, 66));
    public static final SPHINCSPlusParameters sha2_128s = new SPHINCSPlusParameters("sha2-128s-robust", new Sha2EngineProvider(true, 16, 16, 7, 12, 14, 63));
    public static final SPHINCSPlusParameters sha2_192f = new SPHINCSPlusParameters("sha2-192f-robust", new Sha2EngineProvider(true, 24, 16, 22, 8, 33, 66));
    public static final SPHINCSPlusParameters sha2_192s = new SPHINCSPlusParameters("sha2-192s-robust", new Sha2EngineProvider(true, 24, 16, 7, 14, 17, 63));
    public static final SPHINCSPlusParameters sha2_256f = new SPHINCSPlusParameters("sha2-256f-robust", new Sha2EngineProvider(true, 32, 16, 17, 9, 35, 68));
    public static final SPHINCSPlusParameters sha2_256s = new SPHINCSPlusParameters("sha2-256s-robust", new Sha2EngineProvider(true, 32, 16, 8, 14, 22, 64));
    public static final SPHINCSPlusParameters sha2_128f_simple = new SPHINCSPlusParameters("sha2-128f-simple", new Sha2EngineProvider(false, 16, 16, 22, 6, 33, 66));
    public static final SPHINCSPlusParameters sha2_128s_simple = new SPHINCSPlusParameters("sha2-128s-simple", new Sha2EngineProvider(false, 16, 16, 7, 12, 14, 63));
    public static final SPHINCSPlusParameters sha2_192f_simple = new SPHINCSPlusParameters("sha2-192f-simple", new Sha2EngineProvider(false, 24, 16, 22, 8, 33, 66));
    public static final SPHINCSPlusParameters sha2_192s_simple = new SPHINCSPlusParameters("sha2-192s-simple", new Sha2EngineProvider(false, 24, 16, 7, 14, 17, 63));
    public static final SPHINCSPlusParameters sha2_256f_simple = new SPHINCSPlusParameters("sha2-256f-simple", new Sha2EngineProvider(false, 32, 16, 17, 9, 35, 68));
    public static final SPHINCSPlusParameters sha2_256s_simple = new SPHINCSPlusParameters("sha2-256s-simple", new Sha2EngineProvider(false, 32, 16, 8, 14, 22, 64));

    // SHAKE-256.

    public static final SPHINCSPlusParameters shake_128f = new SPHINCSPlusParameters("shake-128f-robust", new Shake256EngineProvider(true, 16, 16, 22, 6, 33, 66));
    public static final SPHINCSPlusParameters shake_128s = new SPHINCSPlusParameters("shake-128s-robust", new Shake256EngineProvider(true, 16, 16, 7, 12, 14, 63));

    public static final SPHINCSPlusParameters shake_192f = new SPHINCSPlusParameters("shake-192f-robust", new Shake256EngineProvider(true, 24, 16, 22, 8, 33, 66));
    public static final SPHINCSPlusParameters shake_192s = new SPHINCSPlusParameters("shake-192s-robust", new Shake256EngineProvider(true, 24, 16, 7, 14, 17, 63));

    public static final SPHINCSPlusParameters shake_256f = new SPHINCSPlusParameters("shake-256f-robust", new Shake256EngineProvider(true, 32, 16, 17, 9, 35, 68));
    public static final SPHINCSPlusParameters shake_256s = new SPHINCSPlusParameters("shake-256s-robust", new Shake256EngineProvider(true, 32, 16, 8, 14, 22, 64));

    public static final SPHINCSPlusParameters shake_128f_simple = new SPHINCSPlusParameters("shake-128f-simple", new Shake256EngineProvider(false, 16, 16, 22, 6, 33, 66));
    public static final SPHINCSPlusParameters shake_128s_simple = new SPHINCSPlusParameters("shake-128s-simple", new Shake256EngineProvider(false, 16, 16, 7, 12, 14, 63));

    public static final SPHINCSPlusParameters shake_192f_simple = new SPHINCSPlusParameters("shake-192f-simple", new Shake256EngineProvider(false, 24, 16, 22, 8, 33, 66));
    public static final SPHINCSPlusParameters shake_192s_simple = new SPHINCSPlusParameters("shake-192s-simple", new Shake256EngineProvider(false, 24, 16, 7, 14, 17, 63));

    public static final SPHINCSPlusParameters shake_256f_simple = new SPHINCSPlusParameters("shake-256f-simple", new Shake256EngineProvider(false, 32, 16, 17, 9, 35, 68));
    public static final SPHINCSPlusParameters shake_256s_simple = new SPHINCSPlusParameters("shake-256s-simple", new Shake256EngineProvider(false, 32, 16, 8, 14, 22, 64));

    // Haraka.

    public static final SPHINCSPlusParameters haraka_128f = new SPHINCSPlusParameters("haraka-128f-robust", new HarakaSEngineProvider(true, 16, 16, 22, 6, 33, 66));
    public static final SPHINCSPlusParameters haraka_128s = new SPHINCSPlusParameters("haraka-128s-robust", new HarakaSEngineProvider(true, 16, 16, 7, 12, 14, 63));

    public static final SPHINCSPlusParameters haraka_256f = new SPHINCSPlusParameters("haraka-256f-robust", new HarakaSEngineProvider(true, 32, 16, 17, 9, 35, 68));
    public static final SPHINCSPlusParameters haraka_256s = new SPHINCSPlusParameters("haraka-256s-robust", new HarakaSEngineProvider(true, 32, 16, 8, 14, 22, 64));

    public static final SPHINCSPlusParameters haraka_192f = new SPHINCSPlusParameters("haraka-192f-robust", new HarakaSEngineProvider(true, 24, 16, 22, 8, 33, 66));
    public static final SPHINCSPlusParameters haraka_192s = new SPHINCSPlusParameters("haraka-192s-robust", new HarakaSEngineProvider(true, 24, 16, 7, 14, 17, 63));

    public static final SPHINCSPlusParameters haraka_128f_simple = new SPHINCSPlusParameters("haraka-128f-simple", new HarakaSEngineProvider(false, 16, 16, 22, 6, 33, 66));
    public static final SPHINCSPlusParameters haraka_128s_simple = new SPHINCSPlusParameters("haraka-128s-simple", new HarakaSEngineProvider(false, 16, 16, 7, 12, 14, 63));

    public static final SPHINCSPlusParameters haraka_192f_simple = new SPHINCSPlusParameters("haraka-192f-simple", new HarakaSEngineProvider(false, 24, 16, 22, 8, 33, 66));
    public static final SPHINCSPlusParameters haraka_192s_simple = new SPHINCSPlusParameters("haraka-192s-simple", new HarakaSEngineProvider(false, 24, 16, 7, 14, 17, 63));

    public static final SPHINCSPlusParameters haraka_256f_simple = new SPHINCSPlusParameters("haraka-256f-simple", new HarakaSEngineProvider(false, 32, 16, 17, 9, 35, 68));
    public static final SPHINCSPlusParameters haraka_256s_simple = new SPHINCSPlusParameters("haraka-256s-simple", new HarakaSEngineProvider(false, 32, 16, 8, 14, 22, 64));

    private static final Integer sphincsPlus_sha2_128f_robust = Integers.valueOf(0x010101);
    private static final Integer sphincsPlus_sha2_128s_robust = Integers.valueOf(0x010102);
    private static final Integer sphincsPlus_sha2_192f_robust = Integers.valueOf(0x010103);
    private static final Integer sphincsPlus_sha2_192s_robust = Integers.valueOf(0x010104);
    private static final Integer sphincsPlus_sha2_256f_robust = Integers.valueOf(0x010105);
    private static final Integer sphincsPlus_sha2_256s_robust = Integers.valueOf(0x010106);

    private static final Integer sphincsPlus_sha2_128f_simple = Integers.valueOf(0x010201);
    private static final Integer sphincsPlus_sha2_128s_simple = Integers.valueOf(0x010202);
    private static final Integer sphincsPlus_sha2_192f_simple = Integers.valueOf(0x010203);
    private static final Integer sphincsPlus_sha2_192s_simple = Integers.valueOf(0x010204);
    private static final Integer sphincsPlus_sha2_256f_simple = Integers.valueOf(0x010205);
    private static final Integer sphincsPlus_sha2_256s_simple = Integers.valueOf(0x010206);

    private static final Integer sphincsPlus_shake_128f_robust = Integers.valueOf(0x020101);
    private static final Integer sphincsPlus_shake_128s_robust = Integers.valueOf(0x020102);
    private static final Integer sphincsPlus_shake_192f_robust = Integers.valueOf(0x020103);
    private static final Integer sphincsPlus_shake_192s_robust = Integers.valueOf(0x020104);
    private static final Integer sphincsPlus_shake_256f_robust = Integers.valueOf(0x020105);
    private static final Integer sphincsPlus_shake_256s_robust = Integers.valueOf(0x020106);

    private static final Integer sphincsPlus_shake_128f_simple = Integers.valueOf(0x020201);
    private static final Integer sphincsPlus_shake_128s_simple = Integers.valueOf(0x020202);
    private static final Integer sphincsPlus_shake_192f_simple = Integers.valueOf(0x020203);
    private static final Integer sphincsPlus_shake_192s_simple = Integers.valueOf(0x020204);
    private static final Integer sphincsPlus_shake_256f_simple = Integers.valueOf(0x020205);
    private static final Integer sphincsPlus_shake_256s_simple = Integers.valueOf(0x020206);

    private static final Integer sphincsPlus_haraka_128f_robust = Integers.valueOf(0x030101);
    private static final Integer sphincsPlus_haraka_128s_robust = Integers.valueOf(0x030102);
    private static final Integer sphincsPlus_haraka_192f_robust = Integers.valueOf(0x030103);
    private static final Integer sphincsPlus_haraka_192s_robust = Integers.valueOf(0x030104);
    private static final Integer sphincsPlus_haraka_256f_robust = Integers.valueOf(0x030105);
    private static final Integer sphincsPlus_haraka_256s_robust = Integers.valueOf(0x030106);

    private static final Integer sphincsPlus_haraka_128f_simple = Integers.valueOf(0x030201);
    private static final Integer sphincsPlus_haraka_128s_simple = Integers.valueOf(0x030202);
    private static final Integer sphincsPlus_haraka_192f_simple = Integers.valueOf(0x030203);
    private static final Integer sphincsPlus_haraka_192s_simple = Integers.valueOf(0x030204);
    private static final Integer sphincsPlus_haraka_256f_simple = Integers.valueOf(0x030205);
    private static final Integer sphincsPlus_haraka_256s_simple = Integers.valueOf(0x030206);

    private static final Map<Integer, SPHINCSPlusParameters> oidToParams = new HashMap<Integer, SPHINCSPlusParameters>();
    private static final Map<SPHINCSPlusParameters, Integer> paramsToOid = new HashMap<SPHINCSPlusParameters, Integer>();

    static {
        oidToParams.put(sphincsPlus_sha2_128f_robust, SPHINCSPlusParameters.sha2_128f);
        oidToParams.put(sphincsPlus_sha2_128s_robust, SPHINCSPlusParameters.sha2_128s);
        oidToParams.put(sphincsPlus_sha2_192f_robust, SPHINCSPlusParameters.sha2_192f);
        oidToParams.put(sphincsPlus_sha2_192s_robust, SPHINCSPlusParameters.sha2_192s);
        oidToParams.put(sphincsPlus_sha2_256f_robust, SPHINCSPlusParameters.sha2_256f);
        oidToParams.put(sphincsPlus_sha2_256s_robust, SPHINCSPlusParameters.sha2_256s);

        oidToParams.put(sphincsPlus_sha2_128f_simple, SPHINCSPlusParameters.sha2_128f_simple);
        oidToParams.put(sphincsPlus_sha2_128s_simple, SPHINCSPlusParameters.sha2_128s_simple);
        oidToParams.put(sphincsPlus_sha2_192f_simple, SPHINCSPlusParameters.sha2_192f_simple);
        oidToParams.put(sphincsPlus_sha2_192s_simple, SPHINCSPlusParameters.sha2_192s_simple);
        oidToParams.put(sphincsPlus_sha2_256f_simple, SPHINCSPlusParameters.sha2_256f_simple);
        oidToParams.put(sphincsPlus_sha2_256s_simple, SPHINCSPlusParameters.sha2_256s_simple);

        oidToParams.put(sphincsPlus_shake_128f_robust, SPHINCSPlusParameters.shake_128f);
        oidToParams.put(sphincsPlus_shake_128s_robust, SPHINCSPlusParameters.shake_128s);
        oidToParams.put(sphincsPlus_shake_192f_robust, SPHINCSPlusParameters.shake_192f);
        oidToParams.put(sphincsPlus_shake_192s_robust, SPHINCSPlusParameters.shake_192s);
        oidToParams.put(sphincsPlus_shake_256f_robust, SPHINCSPlusParameters.shake_256f);
        oidToParams.put(sphincsPlus_shake_256s_robust, SPHINCSPlusParameters.shake_256s);

        oidToParams.put(sphincsPlus_shake_128f_simple, SPHINCSPlusParameters.shake_128f_simple);
        oidToParams.put(sphincsPlus_shake_128s_simple, SPHINCSPlusParameters.shake_128s_simple);
        oidToParams.put(sphincsPlus_shake_192f_simple, SPHINCSPlusParameters.shake_192f_simple);
        oidToParams.put(sphincsPlus_shake_192s_simple, SPHINCSPlusParameters.shake_192s_simple);
        oidToParams.put(sphincsPlus_shake_256f_simple, SPHINCSPlusParameters.shake_256f_simple);
        oidToParams.put(sphincsPlus_shake_256s_simple, SPHINCSPlusParameters.shake_256s_simple);

        oidToParams.put(sphincsPlus_haraka_128f_simple, SPHINCSPlusParameters.haraka_128f_simple);
        oidToParams.put(sphincsPlus_haraka_128f_robust, SPHINCSPlusParameters.haraka_128f);
        oidToParams.put(sphincsPlus_haraka_192f_simple, SPHINCSPlusParameters.haraka_192f_simple);
        oidToParams.put(sphincsPlus_haraka_192f_robust, SPHINCSPlusParameters.haraka_192f);
        oidToParams.put(sphincsPlus_haraka_256f_simple, SPHINCSPlusParameters.haraka_256f_simple);
        oidToParams.put(sphincsPlus_haraka_256f_robust, SPHINCSPlusParameters.haraka_256f);

        oidToParams.put(sphincsPlus_haraka_128s_simple, SPHINCSPlusParameters.haraka_128s_simple);
        oidToParams.put(sphincsPlus_haraka_128s_robust, SPHINCSPlusParameters.haraka_128s);
        oidToParams.put(sphincsPlus_haraka_192s_simple, SPHINCSPlusParameters.haraka_192s_simple);
        oidToParams.put(sphincsPlus_haraka_192s_robust, SPHINCSPlusParameters.haraka_192s);
        oidToParams.put(sphincsPlus_haraka_256s_simple, SPHINCSPlusParameters.haraka_256s_simple);
        oidToParams.put(sphincsPlus_haraka_256s_robust, SPHINCSPlusParameters.haraka_256s);

        paramsToOid.put(SPHINCSPlusParameters.sha2_128f, sphincsPlus_sha2_128f_robust);
        paramsToOid.put(SPHINCSPlusParameters.sha2_128s, sphincsPlus_sha2_128s_robust);
        paramsToOid.put(SPHINCSPlusParameters.sha2_192f, sphincsPlus_sha2_192f_robust);
        paramsToOid.put(SPHINCSPlusParameters.sha2_192s, sphincsPlus_sha2_192s_robust);
        paramsToOid.put(SPHINCSPlusParameters.sha2_256f, sphincsPlus_sha2_256f_robust);
        paramsToOid.put(SPHINCSPlusParameters.sha2_256s, sphincsPlus_sha2_256s_robust);

        paramsToOid.put(SPHINCSPlusParameters.sha2_128f_simple, sphincsPlus_sha2_128f_simple);
        paramsToOid.put(SPHINCSPlusParameters.sha2_128s_simple, sphincsPlus_sha2_128s_simple);
        paramsToOid.put(SPHINCSPlusParameters.sha2_192f_simple, sphincsPlus_sha2_192f_simple);
        paramsToOid.put(SPHINCSPlusParameters.sha2_192s_simple, sphincsPlus_sha2_192s_simple);
        paramsToOid.put(SPHINCSPlusParameters.sha2_256f_simple, sphincsPlus_sha2_256f_simple);
        paramsToOid.put(SPHINCSPlusParameters.sha2_256s_simple, sphincsPlus_sha2_256s_simple);

        paramsToOid.put(SPHINCSPlusParameters.shake_128f, sphincsPlus_shake_128f_robust);
        paramsToOid.put(SPHINCSPlusParameters.shake_128s, sphincsPlus_shake_128s_robust);
        paramsToOid.put(SPHINCSPlusParameters.shake_192f, sphincsPlus_shake_192f_robust);
        paramsToOid.put(SPHINCSPlusParameters.shake_192s, sphincsPlus_shake_192s_robust);
        paramsToOid.put(SPHINCSPlusParameters.shake_256f, sphincsPlus_shake_256f_robust);
        paramsToOid.put(SPHINCSPlusParameters.shake_256s, sphincsPlus_shake_256s_robust);

        paramsToOid.put(SPHINCSPlusParameters.shake_128f_simple, sphincsPlus_shake_128f_simple);
        paramsToOid.put(SPHINCSPlusParameters.shake_128s_simple, sphincsPlus_shake_128s_simple);
        paramsToOid.put(SPHINCSPlusParameters.shake_192f_simple, sphincsPlus_shake_192f_simple);
        paramsToOid.put(SPHINCSPlusParameters.shake_192s_simple, sphincsPlus_shake_192s_simple);
        paramsToOid.put(SPHINCSPlusParameters.shake_256f_simple, sphincsPlus_shake_256f_simple);
        paramsToOid.put(SPHINCSPlusParameters.shake_256s_simple, sphincsPlus_shake_256s_simple);

        paramsToOid.put(SPHINCSPlusParameters.haraka_128f, sphincsPlus_haraka_128f_robust);
        paramsToOid.put(SPHINCSPlusParameters.haraka_192f, sphincsPlus_haraka_192f_robust);
        paramsToOid.put(SPHINCSPlusParameters.haraka_256f, sphincsPlus_haraka_256f_robust);
        paramsToOid.put(SPHINCSPlusParameters.haraka_128s, sphincsPlus_haraka_128s_robust);
        paramsToOid.put(SPHINCSPlusParameters.haraka_192s, sphincsPlus_haraka_192s_robust);
        paramsToOid.put(SPHINCSPlusParameters.haraka_256s, sphincsPlus_haraka_256s_robust);

        paramsToOid.put(SPHINCSPlusParameters.haraka_128f_simple, sphincsPlus_haraka_128f_simple);
        paramsToOid.put(SPHINCSPlusParameters.haraka_192f_simple, sphincsPlus_haraka_192f_simple);
        paramsToOid.put(SPHINCSPlusParameters.haraka_256f_simple, sphincsPlus_haraka_256f_simple);
        paramsToOid.put(SPHINCSPlusParameters.haraka_128s_simple, sphincsPlus_haraka_128s_simple);
        paramsToOid.put(SPHINCSPlusParameters.haraka_192s_simple, sphincsPlus_haraka_192s_simple);
        paramsToOid.put(SPHINCSPlusParameters.haraka_256s_simple, sphincsPlus_haraka_256s_simple);
    }

    private final String name;
    private final SPHINCSPlusEngineProvider engineProvider;

    private SPHINCSPlusParameters(String name, SPHINCSPlusEngineProvider engineProvider) {
        this.name = name;
        this.engineProvider = engineProvider;
    }

    /**
     * Return the SPHINCS+ parameters that map to the passed in parameter ID.
     *
     * @param id the oid of interest.
     * @return the parameter set.
     */
    public static SPHINCSPlusParameters getParams(Integer id) {
        return (SPHINCSPlusParameters) oidToParams.get(id);
    }

    /**
     * Return the OID that maps to the passed in SPHINCS+ parameters.
     *
     * @param params the parameters of interest.
     * @return the OID for the parameter set.
     */
    public static Integer getID(SPHINCSPlusParameters params) {
        return (Integer) paramsToOid.get(params);
    }

    public String getName() {
        return name;
    }

    int getN() {
        return engineProvider.getN();
    }

    SPHINCSPlusEngine getEngine() {
        return engineProvider.get();
    }

    public byte[] getEncoded() {
        return Pack.intToBigEndian(getID(this).intValue());
    }

    private static class Sha2EngineProvider
            implements SPHINCSPlusEngineProvider {
        private final boolean robust;
        private final int n;
        private final int w;
        private final int d;
        private final int a;
        private final int k;
        private final int h;

        public Sha2EngineProvider(boolean robust, int n, int w, int d, int a, int k, int h) {

            this.robust = robust;
            this.n = n;
            this.w = w;
            this.d = d;
            this.a = a;
            this.k = k;
            this.h = h;
        }

        public int getN() {
            return n;
        }

        public SPHINCSPlusEngine get() {
            return HashingProviderProvider.getHashingProvider().getSphincsPlusEngines().getSha2Engine(robust, n, w, d, a, k, h);
        }
    }

    private static class Shake256EngineProvider
            implements SPHINCSPlusEngineProvider {
        private final boolean robust;
        private final int n;
        private final int w;
        private final int d;
        private final int a;
        private final int k;
        private final int h;

        public Shake256EngineProvider(boolean robust, int n, int w, int d, int a, int k, int h) {

            this.robust = robust;
            this.n = n;
            this.w = w;
            this.d = d;
            this.a = a;
            this.k = k;
            this.h = h;
        }

        public int getN() {
            return n;
        }

        public SPHINCSPlusEngine get() {
            return HashingProviderProvider.getHashingProvider().getSphincsPlusEngines().getShake256Engine(robust, n, w, d, a, k, h);
        }
    }

    private static class HarakaSEngineProvider
            implements SPHINCSPlusEngineProvider {
        private final boolean robust;
        private final int n;
        private final int w;
        private final int d;
        private final int a;
        private final int k;
        private final int h;

        public HarakaSEngineProvider(boolean robust, int n, int w, int d, int a, int k, int h) {
            this.robust = robust;
            this.n = n;
            this.w = w;
            this.d = d;
            this.a = a;
            this.k = k;
            this.h = h;
        }

        public int getN() {
            return n;
        }

        public SPHINCSPlusEngine get() {
            return HashingProviderProvider.getHashingProvider().getSphincsPlusEngines().getHarakaSEngine(robust, n, w, d, a, k, h);
        }
    }
}
