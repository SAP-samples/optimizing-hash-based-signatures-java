package org.example.bcpqc.pqc.crypto.xmss;

public class WOTSPlusCtrSignature extends WOTSPlusSignature {
    private final long ctr;

    protected WOTSPlusCtrSignature(WOTSPlusParameters params, byte[][] signature, long ctr) {
        super(params, signature);
        this.ctr = ctr;
    }

    public long getCtr() {
        return ctr;
    }
}
