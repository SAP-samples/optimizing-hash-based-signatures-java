package org.example.jnihash.haraka;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

public class SphincsHarakaSAESNI extends SphincsHarakaS {

    private static final int RATE = 32;
    private final byte[] msg = new byte[RATE];
    public int[] rc;
    SphincsHaraka512AESNI haraka512AESNI = new SphincsHaraka512AESNI();
    private int[] pkSeed;
    private int ofs;

    public void init(byte[] pkSeed) {
        this.pkSeed = ByteUtils.convertToInt(pkSeed);
        genRoundConstants();
        haraka512AESNI.setConstants(this.rc);
    }

    public void update(byte b) {
        throw new RuntimeException("Not implemented");
    }

    /**
     * write to input stream
     *
     * @param data   bytes to be written
     * @param offset offset
     * @param length length of byte array in bytes (not bits!)
     */
    public void update(byte[] data, int offset, int length) {
        if (ofs + length >= RATE) {
            for (int i = 0; i < ofs; i++) {
                this.state[i] ^= msg[i];
            }
            for (int i = 0; i < (RATE - ofs); i++) {
                this.state[ofs + i] ^= data[offset + i];
            }
            offset += (RATE - ofs);
            length -= (RATE - ofs);
            this.ofs = 0;
            this.state = haraka512AESNI.permute(this.state);
        }

        while (length >= RATE) {
            for (int i = 0; i < RATE; ++i) {
                this.state[i] ^= data[offset + i];
            }
            this.state = haraka512AESNI.permute(this.state);
            offset += RATE;
            length -= RATE;
        }

        if (length > 0) {
            System.arraycopy(data, offset, this.msg, ofs, length);
            ofs += length;
        }
    }

    /**
     * compability reasons
     *
     * @return null
     */
    public byte[] digest() {
        return null;
    }

    /**
     * @param r squeezing r bits of the previously provided input.
     * @return the squeezed bits.
     */
    public byte[] digest(int r) {
        int blocks = (int) Math.ceil((double) (r / 8) / (double) RATE);
        if (blocks == 0)
            blocks = 1;
        byte[] result;
        absorbPadding();
        result = squeeze(blocks);
        if ((r / 8) % RATE != 0) {
            //we don't need all the bytes we squeezed so we throw the last few away
            return Arrays.copyOf(result, result.length - ((RATE * blocks) - (r / 8)));
        }
        return result;
    }

    @Override
    public int[] getConstants() {
        return this.rc;
    }

    @Override
    public void setConstants(int[] in) {
        this.rc = in;
    }

    /**
     * round constants first created from the original ones
     */
    private void genRoundConstants() {
        byte[] tmp;
        reset();
        this.update(ByteUtils.convertToByte(this.pkSeed), 0, this.pkSeed.length * 4);
        absorbPadding();
        tmp = squeeze(20);
        reset();
        rc = ByteUtils.convertToLeInt(tmp);
    }

    /**
     * absorb the last block, i.e. the last message bytes in msg (if any) and the padding
     */
    private void absorbPadding() {
        //consume all other bytes or an empty array for padding
        int i;
        for(i = 0; i < ofs; i++){
            this.state[i] ^= msg[i];
        }

        this.state[i] ^= 0x1F;
        this.state[RATE - 1] ^= 0x80;
    }

    /**
     * we obtain a d-bit hash to squeeze blocks of r bits
     * d is always 512 since it's a haraka round
     *
     * @param blocks the nr of blocks to squeeze
     * @return the squeezed byte string
     */
    private byte[] squeeze(int blocks) {
        byte[] out = new byte[blocks * RATE];
        for(int i = 0; i < blocks; i++){
            this.state = haraka512AESNI.permute(this.state);
            System.arraycopy(this.state, 0, out, i * RATE, RATE);
        }
        return out;
    }

    @Override
    public void reset() {
        this.state = new byte[64];
        this.ofs = 0;
    }
}