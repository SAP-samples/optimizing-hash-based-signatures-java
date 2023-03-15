package org.example.jnihash.haraka;


import java.io.ByteArrayOutputStream;

import static org.example.jnihash.haraka.ByteUtils.convertToByte;
import static org.example.jnihash.haraka.ByteUtils.convertToInt;
import static org.example.jnihash.haraka.SphincsHarakaConst.aesRound;

public class SphincsHaraka256Soft extends SphincsHaraka256 {
    // use getBytes for strings
    private int[] rc; //round constants, which need to be changable for SPHINCS+

    protected ByteArrayOutputStream msg = new ByteArrayOutputStream();

    /**
     * initialize properties
     * this hash functions should use big endian, bit magic is used to make it little endian (as in intel)
     */
    public SphincsHaraka256Soft() {
        this.rc = SphincsHarakaConst.roundConstants;
    }


    @Override
    /**
     * single byte
     */
    public void update(byte b) {
        msg.write(b);
    }


    @Override
    /**
     * entire array
     * @param bytes bytearray
     * @param i offset
     * @param i1 length
     * using ByteArrayOutputStream for convenience
     */ public void update(byte[] bytes, int i, int i1) {
        msg.write(bytes, i, i1);
    }

    @Override
    public void reset() {
        this.msg.reset();
    }

    @Override
    public byte[] digest() {
        if (this.msg.size() != 32) {
            System.out.println("Message size not 256 bits");
            return null;
        }
        int[] result = convertToInt(this.msg.toByteArray());
        byte[] message = this.msg.toByteArray();
        int i = 0;
        int[] keys = new int[4];
        int[] block0 = new int[4];
        int[] block1 = new int[4];
        byte[] intermediate = new byte[32];
        while (i < ROUNDS) {
            System.arraycopy(result, 0, block0, 0, 4);
            System.arraycopy(result, 4, block1, 0, 4);

            //AES, first and second round, for each block
            for (int j = 0; j < AES_ROUNDS; j++) {
                // stitch round constants together
                keys[0] = rc[4 * (2 * AES_ROUNDS * i + 2 * j)];
                keys[1] = rc[4 * (2 * AES_ROUNDS * i + 2 * j) + 1];
                keys[2] = rc[4 * (2 * AES_ROUNDS * i + 2 * j) + 2];
                keys[3] = rc[4 * (2 * AES_ROUNDS * i + 2 * j) + 3];

                // first AES round
                block0 = aesRound(block0, keys);

                // stitch round keys together
                keys[0] = rc[4 * (2 * AES_ROUNDS * i + 2 * j + 1)];
                keys[1] = rc[4 * (2 * AES_ROUNDS * i + 2 * j + 1) + 1];
                keys[2] = rc[4 * (2 * AES_ROUNDS * i + 2 * j + 1) + 2];
                keys[3] = rc[4 * (2 * AES_ROUNDS * i + 2 * j + 1) + 3];

                block1 = aesRound(block1, keys);
            }

            //mixing
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(convertToByte(block0), 0, 16);
            outputStream.write(convertToByte(block1), 0, 16);

            intermediate = mixing(outputStream.toByteArray());
            result = convertToInt(intermediate);
            i += 1;

        }

        //finally xor result and message for DM effect
        for (i = 0; i < 32; ++i) {
            intermediate[i] ^= message[i];
        }

        return intermediate;
    }

    @Override
    /**
     * needed for sphincs+ to change round constants
     * twice, because reflection doesn't find it if in Haraka
     * @param rc change round constants
     */
    public void setConstants(int[] rc) {
        this.rc = rc;
    }

    @Override
    public int[] getConstants() {
        return this.rc;
    }



    /**
     * omega network-like shuffling of the message blocks
     * tested
     * column 0 --> 0
     * column 1 --> 2
     * column 2 --> 4
     * column 3 --> 6
     * column 4 --> 1
     * column 5 --> 3
     * column 6 --> 5
     * column 7 --> 7
     *
     * @param message, assumed to be a byte array
     * @return shuffled message
     */
    private byte[] mixing(byte[] message) {
        byte[] mixed = new byte[32];
        System.arraycopy(message, 0, mixed, 0, 4);
        System.arraycopy(message, 4, mixed, 8, 4);
        System.arraycopy(message, 8, mixed, 16, 4);
        System.arraycopy(message, 12, mixed, 24, 4);
        System.arraycopy(message, 16, mixed, 4, 4);
        System.arraycopy(message, 20, mixed, 12, 4);
        System.arraycopy(message, 24, mixed, 20, 4);
        System.arraycopy(message, 28, mixed, 28, 4);

        return mixed;
    }


}


