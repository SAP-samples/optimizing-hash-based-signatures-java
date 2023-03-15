package org.example.bcpqc.pqc.crypto.lms;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.example.bcpqc.experiments.hashing.HashingProviderProvider;
import org.example.bcpqc.pqc.crypto.lms.hash.LMSHash;

class SeedDerive {
    private final byte[] I;
    private final byte[] masterSeed;
    private final ASN1ObjectIdentifier digestOid;
    private final LMSHash lmsHash;
    private int q;
    private int j;

    private int digestLength;


    public SeedDerive(byte[] I, byte[] masterSeed, ASN1ObjectIdentifier digestOid, int digestLength) {
        this.I = I;
        this.masterSeed = masterSeed;
        this.digestLength = digestLength;
        this.digestOid = digestOid;
        this.lmsHash  = HashingProviderProvider.getHashingProvider().newLMSHash(this.digestOid, this.digestLength);
    }

    public int getQ() {
        return q;
    }

    public void setQ(int q) {
        this.q = q;
    }

    public int getJ() {
        return j;
    }

    public void setJ(int j) {
        this.j = j;
    }

    public byte[] getI() {
        return I;
    }

    public byte[] getMasterSeed() {
        return masterSeed;
    }


    public byte[] deriveSeed(byte[] target) {
        lmsHash.otsChain(I, q, j, 0xFF, masterSeed, target);

        return target;
    }

    public void deriveSeed(byte[] target, boolean incJ) {
        deriveSeed(target, incJ, 0);
    }


    public void deriveSeed(byte[] target, boolean incJ, int offset) {
        if(offset != 0){
            throw new IllegalArgumentException("Unsupported");
        }

        deriveSeed(target);

        if (incJ) {
            j++;
        }

    }
}
