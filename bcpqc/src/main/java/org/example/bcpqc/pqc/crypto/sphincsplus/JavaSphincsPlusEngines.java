package org.example.bcpqc.pqc.crypto.sphincsplus;

public class JavaSphincsPlusEngines implements SPHINCSPlusEngines {

    public static final JavaSphincsPlusEngines INSTANCE = new JavaSphincsPlusEngines();

    private JavaSphincsPlusEngines() {

    }

    @Override
    public SPHINCSPlusEngine getSha2Engine(boolean robust, int n, int w, int d, int a, int k, int h) {
        return new JavaSha2Engine(robust, n, w, d, a, k, h);
    }

    @Override
    public SPHINCSPlusEngine getShake256Engine(boolean robust, int n, int w, int d, int a, int k, int h) {
        return new JavaShake256Engine(robust, n, w, d, a, k, h);
    }

    @Override
    public SPHINCSPlusEngine getHarakaSEngine(boolean robust, int n, int w, int d, int a, int k, int h) {
        return new JavaHarakaSEngine(robust, n, w, d, a, k, h);
    }
}
