package org.example.jnihash.haraka;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import static org.example.jnihash.haraka.ByteUtils.*;
import static org.example.jnihash.haraka.SphincsHarakaConst.aesRound;

public class SphincsHarakaSSoft extends SphincsHarakaS {
    private static final int ROUNDS = 5;
    private static final int AES_ROUNDS = 2;
    private static final int RATE = 32;
    private int[] pkSeed;
    public int[] rc;

    protected ByteArrayOutputStream msg = new ByteArrayOutputStream();

    public SphincsHarakaSSoft() {
        this.rc = SphincsHarakaConst.roundConstants;
    }

    @Override
    public void update(byte[] bytes, int offset, int length) {
        msg.write(bytes, offset, length);
    }

    public void init(byte[] pkSeed) {
        this.pkSeed = convertToInt(pkSeed);
        genRoundConstants();
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
        int blocks = (int) Math.ceil((double)(r / 8) / (double)RATE);
        byte[] result;
        absorb();
        result = squeeze(blocks);
        if ((r / 8) % RATE != 0) {
            //we don't need all the bytes we squeezed so we throw the last few away
            return Arrays.copyOf(result, result.length - ((RATE * blocks) - (r / 8)));
        }
        return result;
    }

    public void reset() {
        this.msg.reset();
        this.state=new byte[64];
    }


    /**
     * round constants first created from the original ones
     */
    private void genRoundConstants() {
        byte[] tmp;
        reset();
        this.msg.write(convertToByte(this.pkSeed), 0, this.pkSeed.length * 4);
        absorb();
        tmp = squeeze(20);
        rc = convertToInt(tmp);
        reset();
        //rc = convertConstants(tmp);
    }

    /**
     * absorb the content of the message block by block
     * and padding the rest (according to standard)
     * <p>
     * first, the message is checked and if needed padded
     * the sponge capacity is added and only in this step touched
     * <p>
     * then, the message is block-wise added.
     * <p>
     * in the last step, all remaining bits are consumed
     */
    private void absorb() {
        //The class variable state is altered, since we need to xor the message parts, but shouldn't touch the capacity.
        byte[] m;
        m = msg.toByteArray();
        int msize = msg.size();
        int i, j = 0;

        while (msize >= RATE) {
            // state will be initialized with 0
            for (i = 0; i < RATE; ++i) {
                this.state[i] ^= m[i + (j * RATE)];
            }
            this.state = haraka512Perm(this.state);
            msize -= RATE;
            j++;
        }

        //consume all other bytes or an empty array for padding
        byte[] unpadded = new byte[msize];
        byte[] padded;
        for (i = 0; i < msize; ++i) {
            unpadded[i] = m[i + (j * RATE)];
        }
        //do pad
        padded = shakePad(unpadded);
        //XOR with state
        for (i = 0; i < RATE; ++i) {
            this.state[i] ^= padded[i];
        }
    }

    /**
     * we obtain a d-bit hash to squeeze blocks of r bits
     * d is always 512 since it's a haraka round
     *
     * @param blocks the nr of blocks to squeeze
     * @return the squeezed byte string
     */
    private byte[] squeeze(int blocks) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while (blocks > 0) {
            this.state = haraka512Perm(this.state);
            out.write(this.state, 0, 32);
            blocks--;
        }
        return out.toByteArray();
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
     * @return truncated hash of 256 bit
     */
    private static byte[] truncate(byte[] hash) {
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

    private byte[] haraka512Perm(byte[] message) {
        int[] result = convertToInt(message);
        byte[] intermediate;
        int[] keys = new int[4];
        int[] block0 = new int[4];
        int[] block1 = new int[4];
        int[] block2 = new int[4];
        int[] block3 = new int[4];
        int i = 0;
        while (i < ROUNDS) {
            System.arraycopy(result, 0, block0, 0, 4);
            System.arraycopy(result, 4, block1, 0, 4);
            System.arraycopy(result, 8, block2, 0, 4);
            System.arraycopy(result, 12, block3, 0, 4);

            //AES, first and second round, for each block
            for (int j = 0; j < AES_ROUNDS; j++) {
                // stitch round constants together, reverse order because of little endian
                keys[0] = rc[4 * (4 * AES_ROUNDS * i + 4 * j) + 3];
                keys[1] = rc[4 * (4 * AES_ROUNDS * i + 4 * j) + 2];
                keys[2] = rc[4 * (4 * AES_ROUNDS * i + 4 * j) + 1];
                keys[3] = rc[4 * (4 * AES_ROUNDS * i + 4 * j)];

                // first AES round
                block0 = aesRound(block0, keys);

                // stitch round keys together
                keys[0] = rc[4 * (4 * AES_ROUNDS * i + 4 * j + 1) + 3];
                keys[1] = rc[4 * (4 * AES_ROUNDS * i + 4 * j + 1) + 2];
                keys[2] = rc[4 * (4 * AES_ROUNDS * i + 4 * j + 1) + 1];
                keys[3] = rc[4 * (4 * AES_ROUNDS * i + 4 * j + 1)];

                block1 = aesRound(block1, keys);

                keys[0] = rc[4 * (4 * AES_ROUNDS * i + 4 * j + 2) + 3];
                keys[1] = rc[4 * (4 * AES_ROUNDS * i + 4 * j + 2) + 2];
                keys[2] = rc[4 * (4 * AES_ROUNDS * i + 4 * j + 2) + 1];
                keys[3] = rc[4 * (4 * AES_ROUNDS * i + 4 * j + 2)];

                block2 = aesRound(block2, keys);

                keys[0] = rc[4 * (4 * AES_ROUNDS * i + 4 * j + 3) + 3];
                keys[1] = rc[4 * (4 * AES_ROUNDS * i + 4 * j + 3) + 2];
                keys[2] = rc[4 * (4 * AES_ROUNDS * i + 4 * j + 3) + 1];
                keys[3] = rc[4 * (4 * AES_ROUNDS * i + 4 * j + 3)];

                block3 = aesRound(block3, keys);
            }
            //mixing
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(convertToByte(block0), 0, 4 * block0.length);
            outputStream.write(convertToByte(block1), 0, 4 * block1.length);
            outputStream.write(convertToByte(block2), 0, 4 * block2.length);
            outputStream.write(convertToByte(block3), 0, 4 * block3.length);

            intermediate = mixing(outputStream.toByteArray());
            result = convertToInt(intermediate);
            i++;
        }
        return convertToByte(result);

    }

    /**
     * entire haraka, including the truncation, for completeness
     *
     * @param message message to be hashed
     * @return truncated hash
     */
    protected byte[] round(byte[] message) {
        byte[] finale;
        byte[] intermediate = haraka512Perm(message);

        //finally xor result and message for DM effect
        for (int i = 0; i < 64; ++i) {
            intermediate[i] ^= message[i];
        }
        finale = truncate(intermediate);
        return finale;
    }


    /**
     * needed for sphincs+ to change round constants
     *
     * @param rc change round constants
     */
    public void setConstants(int[] rc) {
        this.rc = rc;
    }

    /**
     * needed for sphincs+ to change round constants
     */
    public int[] getConstants() {
        return this.rc;
    }

}

