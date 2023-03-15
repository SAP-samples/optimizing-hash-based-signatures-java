package org.example.bcpqc.pqc.crypto.sphincsplus;

public class MGF1Utils {

    static void ItoOSP(int i, byte[] sp) {
        sp[0] = (byte) (i >>> 24);
        sp[1] = (byte) (i >>> 16);
        sp[2] = (byte) (i >>> 8);
        sp[3] = (byte) (i);
    }

}
