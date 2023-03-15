package org.example.bcpqc.pqc.crypto.sphincsplus;

public interface SPHINCSPlusEngines {
    SPHINCSPlusEngine getSha2Engine(boolean robust, int n, int w, int d, int a, int k, int h);

    SPHINCSPlusEngine getShake256Engine(boolean robust, int n, int w, int d, int a, int k, int h);

    SPHINCSPlusEngine getHarakaSEngine(boolean robust, int n, int w, int d, int a, int k, int h);
}
