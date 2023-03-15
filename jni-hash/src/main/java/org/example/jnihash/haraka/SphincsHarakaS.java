package org.example.jnihash.haraka;

public abstract class SphincsHarakaS extends Haraka {

    protected byte[] state = new byte[64];
    SphincsHarakaS() {

    }

    public abstract byte[] digest();

    public abstract byte[] digest(int r);

    public abstract void setConstants(int[] in);
    public abstract int[] getConstants();
    public abstract void init(byte[] pkSeed);

}
