package org.example.bcpqc.pqc.crypto.sphincsplus;

public class JNISphincsPlusEngines implements SPHINCSPlusEngines {
    public static final JNISphincsPlusEngines INSTANCE = new JNISphincsPlusEngines();

    private JNISphincsPlusEngines() {

    }


    @Override
    public SPHINCSPlusEngine getSha2Engine(boolean robust, int n, int w, int d, int a, int k, int h) {
        return null;
        //return new BCSha2Engine(robust, n, w, d, a, k, h);
    }

    @Override
    public SPHINCSPlusEngine getShake256Engine(boolean robust, int n, int w, int d, int a, int k, int h) {
        return new JNIShake256Engine(robust, n, w, d, a, k, h);
    }

    @Override
    public SPHINCSPlusEngine getHarakaSEngine(boolean robust, int n, int w, int d, int a, int k, int h) {
        return new JniHarakaSEngine(robust, n, w, d, a, k, h);
    }
}
