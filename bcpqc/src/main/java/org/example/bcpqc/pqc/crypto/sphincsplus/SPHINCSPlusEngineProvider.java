package org.example.bcpqc.pqc.crypto.sphincsplus;


interface SPHINCSPlusEngineProvider {
    int getN();

    SPHINCSPlusEngine get();
}
