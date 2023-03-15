package org.example.bcpqc.pqc.crypto.sphincsplus;

public class BCSphincsPlusEngines implements SPHINCSPlusEngines {
    public static final BCSphincsPlusEngines INSTANCE = new BCSphincsPlusEngines();

    private BCSphincsPlusEngines() {

    }


    @Override
    public SPHINCSPlusEngine getSha2Engine(boolean robust, int n, int w, int d, int a, int k, int h) {
        return new BCSha2Engine(robust, n, w, d, a, k, h);
    }

    @Override
    public SPHINCSPlusEngine getShake256Engine(boolean robust, int n, int w, int d, int a, int k, int h) {
        return new BCShake256Engine(robust, n, w, d, a, k, h);
    }

    @Override
    public SPHINCSPlusEngine getHarakaSEngine(boolean robust, int n, int w, int d, int a, int k, int h) {
        return new BCHarakaSEngine(robust, n, w, d, a, k, h);
    }
}
