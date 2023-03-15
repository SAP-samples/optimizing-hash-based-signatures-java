package org.example.jnihash.haraka;

public abstract class SphincsHaraka256 extends Haraka {

    public abstract byte[] digest();
    public abstract void setConstants(int[] in);
    public abstract int[] getConstants();

}
