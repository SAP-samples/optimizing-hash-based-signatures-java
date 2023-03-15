package org.example.jnihash.haraka;

import java.io.ByteArrayOutputStream;

import static org.example.jnihash.haraka.ByteUtils.*;
import static org.example.jnihash.haraka.SphincsHarakaConst.aesRound;


public class SphincsHaraka512Soft extends SphincsHaraka512 {
    static final int ROUNDS = 5;
    private int[] rc;

    protected ByteArrayOutputStream msg = new ByteArrayOutputStream();

    public SphincsHaraka512Soft() {
        rc = SphincsHarakaConst.roundConstants;
    }

    public void update(byte[] bytes, int i, int i1) {
        msg.write(bytes, i, i1);
    }

    public void reset() {
        this.msg.reset();
    }

    @Override
    public byte[] digest() {

        if (this.msg.size() != 64) {
            // pad if necessary, the input might not be large enough.
            this.update(padByte(64-msg.size()), 0, 64-msg.size());
        }
        int[] result = convertToInt(this.msg.toByteArray());
        byte[] message = this.msg.toByteArray();
        int i = 0;
        int[] keys = new int[4];
        int[] block0 = new int[4];
        int[] block1 = new int[4];
        int[] block2 = new int[4];
        int[] block3 = new int[4];
        byte[] intermediate = new byte[64];
        byte[] finale;
        while (i < ROUNDS) {
            System.arraycopy(result, 0, block0, 0, 4);
            System.arraycopy(result, 4, block1, 0, 4);
            System.arraycopy(result, 8, block2, 0, 4);
            System.arraycopy(result, 12, block3, 0, 4);

            //AES, first and second round, for each block
            for (int j = 0; j < AES_ROUNDS; j++) {
                // stitch round constants together, reverse order because of little endian
                keys[0] = rc[4 * (4 * AES_ROUNDS * i + 4 * j)];
                keys[1] = rc[4 * (4 * AES_ROUNDS * i + 4 * j) + 1];
                keys[2] = rc[4 * (4 * AES_ROUNDS * i + 4 * j) + 2];
                keys[3] = rc[4 * (4 * AES_ROUNDS * i + 4 * j) + 3];

                // first AES round
                block0 = aesRound(block0, keys);

                // stitch round keys together
                keys[0] = rc[4 * (4 * AES_ROUNDS * i + 4 * j + 1)];
                keys[1] = rc[4 * (4 * AES_ROUNDS * i + 4 * j + 1) + 1];
                keys[2] = rc[4 * (4 * AES_ROUNDS * i + 4 * j + 1) + 2];
                keys[3] = rc[4 * (4 * AES_ROUNDS * i + 4 * j + 1) + 3];

                block1 = aesRound(block1, keys);

                keys[0] = rc[4 * (4 * AES_ROUNDS * i + 4 * j + 2)];
                keys[1] = rc[4 * (4 * AES_ROUNDS * i + 4 * j + 2) + 1];
                keys[2] = rc[4 * (4 * AES_ROUNDS * i + 4 * j + 2) + 2];
                keys[3] = rc[4 * (4 * AES_ROUNDS * i + 4 * j + 2) + 3];

                block2 = aesRound(block2, keys);

                keys[0] = rc[4 * (4 * AES_ROUNDS * i + 4 * j + 3)];
                keys[1] = rc[4 * (4 * AES_ROUNDS * i + 4 * j + 3) + 1];
                keys[2] = rc[4 * (4 * AES_ROUNDS * i + 4 * j + 3) + 2];
                keys[3] = rc[4 * (4 * AES_ROUNDS * i + 4 * j + 3) + 3];

                block3 = aesRound(block3, keys);
            }

            //mixing
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(convertToByte(block0), 0, block0.length*4);
            outputStream.write(convertToByte(block1), 0, block1.length*4);
            outputStream.write(convertToByte(block2), 0, block2.length*4);
            outputStream.write(convertToByte(block3), 0, block3.length*4);
            intermediate = mixing(outputStream.toByteArray());
            result = convertToInt(intermediate);
            i += 1;

        }

        //finally xor result and message for DM effect
        for (i = 0; i < 64; ++i) {
            intermediate[i] ^= message[i];
        }
        finale = truncate(intermediate);
        return finale;
    }

    @Override
    public void setConstants(int[] in) {
        this.rc=in;
    }

    @Override
    public int[] getConstants() {
        return this.rc;
    }

    /**
     * implementing mixing function
     *
     * @param message unpermuted message
     * @return permuted message
     */
    private static byte[] mixing(byte[] message) {
        byte[] mixed = new byte[64];
        System.arraycopy(message, 0, mixed, 20, 4);
        System.arraycopy(message, 4, mixed, 36, 4);
        System.arraycopy(message, 8, mixed, 48, 4);
        System.arraycopy(message, 12, mixed, 0, 4);
        System.arraycopy(message, 16, mixed, 28, 4);
        System.arraycopy(message, 20, mixed, 44, 4);
        System.arraycopy(message, 24, mixed, 56, 4);
        System.arraycopy(message, 28, mixed, 8, 4);
        System.arraycopy(message, 32, mixed, 16, 4);
        System.arraycopy(message, 36, mixed, 32, 4);
        System.arraycopy(message, 40, mixed, 52, 4);
        System.arraycopy(message, 44, mixed, 4, 4);
        System.arraycopy(message, 48, mixed, 24, 4);
        System.arraycopy(message, 52, mixed, 40, 4);
        System.arraycopy(message, 56, mixed, 60, 4);
        System.arraycopy(message, 60, mixed, 12, 4);

        return mixed;
    }

    /**
     * Truncate the 512 bit hash
     * concate two colums from each block- the least significant ones from the first two blocks (2 & 3, 6 & 7)
     * and the most significant ones from the last two blocks (8 & 9, 12 & 13)
     *
     * @param hash 512 bit hash
     * @return
     */
    protected static byte[] truncate(byte[] hash) {
        byte[] truncated = new byte[32];
        System.arraycopy(hash, 8, truncated, 0, 4);
        System.arraycopy(hash, 12, truncated, 4, 4);
        System.arraycopy(hash, 24, truncated, 8, 4);
        System.arraycopy(hash, 28, truncated, 12, 4);
        System.arraycopy(hash, 32, truncated, 16, 4);
        System.arraycopy(hash, 36, truncated, 20, 4);
        System.arraycopy(hash, 48, truncated, 24, 4);
        System.arraycopy(hash, 52, truncated, 28, 4);
        return truncated;
    }

}

