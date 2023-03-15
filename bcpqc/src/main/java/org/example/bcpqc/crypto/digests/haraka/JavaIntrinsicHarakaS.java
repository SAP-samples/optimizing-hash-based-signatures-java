package org.example.bcpqc.crypto.digests.haraka;

import com.sun.crypto.provider.AESCrypt;
import com.sun.crypto.provider.ElectronicCodeBook;

import java.util.Arrays;

// Adopts code from https://extgit.iaik.tugraz.at/krypto/javasphincsplus/-/blob/master/src/at/iaik/pq/sphincs/utils/HarakaUtils/SphincsHarakaSAESNI.java
public class JavaIntrinsicHarakaS {
    private static final byte[] DEFAULT_RC = {-99, 123, -127, 117, -16, -2, -59, -78, 10, -64, 32, -26, 76, 112, -124, 6, 23, -9, 8, 47, -92, 107, 15, 100, 107, -96, -13, -120, -31, -76, 102, -117, 20, -111, 2, -97, 96, -99, 2, -49, -104, -124, -14, 83, 45, -34, 2, 52, 121, 79, 91, -3, -81, -68, -13, -69, 8, 79, 123, 46, -26, -22, -42, 14, 68, 112, 57, -66, 28, -51, -18, 121, -117, 68, 114, 72, -53, -80, -49, -53, 123, 5, -118, 43, -19, 53, 83, -115, -73, 50, -112, 110, -18, -51, -22, 126, 27, -17, 79, -38, 97, 39, 65, -30, -48, 124, 46, 94, 67, -113, -62, 103, 59, 11, -57, 31, -30, -3, 95, 103, 7, -52, -54, -81, -80, -39, 36, 41, -18, 101, -44, -71, -54, -113, -37, -20, -23, 127, -122, -26, -15, 99, 77, -85, 51, 126, 3, -83, 79, 64, 42, 91, 100, -51, -73, -44, -124, -65, 48, 28, 0, -104, -10, -115, 46, -117, 2, 105, -65, 35, 23, -108, -71, 11, -52, -78, -118, 45, -99, 92, -56, -98, -86, 74, 114, 85, 111, -34, -90, 120, 4, -6, -44, -97, 18, 41, 46, 79, -6, 14, 18, 42, 119, 107, 43, -97, -76, -33, -18, 18, 106, -69, -82, 17, -42, 50, 54, -94, 73, -12, 68, 3, -95, 30, -90, -20, -88, -100, -55, 0, -106, 95, -124, 0, 5, 75, -120, 73, 4, -81, -20, -109, -27, 39, -29, -57, -94, 120, 79, -100, 25, -99, -40, 94, 2, 33, 115, 1, -44, -126, -51, 46, 40, -71, -73, -55, 89, -89, -8, -86, 58, -65, 107, 125, 48, 16, -39, -17, -14, 55, 23, -80, -122, 97, 13, 112, 96, 98, -58, -102, -4, -10, 83, -111, -62, -127, 67, 4, 48, 33, -62, 69, -54, 90, 58, -108, -47, 54, -24, -110, -81, 44, -69, 104, 107, 34, 60, -105, 35, -110, -76, 113, 16, -27, 88, -71, -70, 108, -21, -122, 88, 34, 56, -110, -65, -45, -115, 18, -31, 36, -35, -3, 61, -109, 119, -58, -16, -82, -27, 60, -122, -37, -79, 18, 34, -53, -29, -115, -28, -125, -100, -96, -21, -1, 104, 98, 96, -69, 125, -9, 43, -57, 78, 26, -71, 45, -100, -47, -28, -30, -36, -45, 75, 115, 78, -110, -77, 44, -60, 21, 20, 75, 67, 27, 48, 97, -61, 71, -69, 67, -103, 104, -21, 22, -35, 49, -78, 3, -10, -17, 7, -25, -88, 117, -89, -37, 44, 71, -54, 126, 2, 35, 94, -114, 119, 89, 117, 60, 75, 97, -13, 109, -7, 23, -122, -72, -71, -27, 27, 109, 119, 125, -34, -42, 23, 90, -89, -51, 93, -18, 70, -87, -99, 6, 108, -99, -86, -23, -88, 107, -16, 67, 107, -20, -63, 39, -13, 59, 89, 17, 83, -94, 43, 51, 87, -7, 80, 105, 30, -53, -39, -48, 14, 96, 83, 3, -19, -28, -100, 97, -38, 0, 117, 12, -18, 44, 80, -93, -92, 99, -68, -70, -69, -128, -85, 12, -23, -106, -95, -91, -79, -16, 57, -54, -115, -109, 48, -34, 13, -85, -120, 41, -106, 94, 2, -79, 61, -82, 66, -76, 117, 46, -88, -13, 20, -120, 11, -92, 84, -43, 56, -113, -69, 23, -10, 22, 10, 54, 121, -73, -74, -82, -41, 127, 66, 95, 91, -118, -69, 52, -34, -81, -70, -1, 24, 89, -50, 67, 56, 84, -27, -53, 65, 82, -10, 38, 120, -55, -98, -125, -9, -100, -54, -94, 106, 2, -13, -71, 84, -102, -23, 76, 53, 18, -112, 34, 40, 110, -64, 64, -66, -9, -33, 27, 26, -91, 81, -82, -49, 89, -90, 72, 15, -68, 115, -63, 43, -46, 126, -70, 60, 97, -63, -96, -95, -99, -59, -23, -3, -67, -42, 74, -120, -126, 40, 2, 3, -52, 106, 117,};
    private static final int RATE = 32;
    final AESCrypt aesCrypt;
    final ElectronicCodeBook electronicCodeBook;
    private final byte[] buf = new byte[64];
    private byte[] state = new byte[64];
    private int ofs = 0;
    private byte[] rc = null;
    private byte[] pkSeed;

    public JavaIntrinsicHarakaS() {
        this.aesCrypt = new AESCrypt();
        this.electronicCodeBook = new ElectronicCodeBook(aesCrypt);
    }

    public byte[] getRCs() {
        return (rc == null) ? DEFAULT_RC : rc;
    }

    public void update(byte[] data, int offset, int length) {
        if (ofs + length >= RATE) {
            for (int i = 0; i < ofs; i++) {
                this.state[i] ^= buf[i];
            }
            for (int i = 0; i < (RATE - ofs); i++) {
                this.state[ofs + i] ^= data[offset + i];
            }
            offset += (RATE - ofs);
            length -= (RATE - ofs);
            this.ofs = 0;
            // Haraka512 permutation
            aesCrypt.decryptBlock(this.state, 0, getRCs(), 0);
        }

        while (length >= RATE) {
            for (int i = 0; i < RATE; ++i) {
                this.state[i] ^= data[offset + i];
            }
            // Haraka512 permutation
            aesCrypt.decryptBlock(this.state, 0, getRCs(), 0);

            offset += RATE;
            length -= RATE;
        }

        if (length > 0) {
            System.arraycopy(data, offset, this.buf, ofs, length);
            ofs += length;
        }
    }

    private void absorbPadding() {
        //consume all other bytes or an empty array for padding
        int i;
        for (i = 0; i < ofs; i++) {
            this.state[i] ^= buf[i];
        }

        this.state[i] ^= 0x1F;
        this.state[RATE - 1] ^= 0x80;
    }

    private byte[] squeeze(int blocks) {
        byte[] out = new byte[blocks * RATE];
        for (int i = 0; i < blocks; i++) {
            // Haraka512 permutation
            aesCrypt.decryptBlock(this.state, 0, getRCs(), 0);
            System.arraycopy(this.state, 0, out, i * RATE, RATE);
        }
        return out;
    }

    public void reset() {
        this.state = new byte[64];
        this.ofs = 0;
    }

    public byte[] digest(int r) {
        int blocks = (int) Math.ceil((double) r / (double) RATE);
        if (blocks == 0)
            blocks = 1;
        byte[] result;
        absorbPadding();
        result = squeeze(blocks);
        if (r % RATE != 0) {
            //we don't need all the bytes we squeezed so we throw the last few away
            return Arrays.copyOf(result, result.length - ((RATE * blocks) - r));
        }
        return result;
    }

    public void init(byte[] pkSeed) {
        // Use default round constants for roundConstant calculation
        this.rc = null;
        this.pkSeed = pkSeed;
        genRoundConstants();
    }

    public JavaIntrinsicHarakaS clone() {
        JavaIntrinsicHarakaS clone = new JavaIntrinsicHarakaS();
        clone.rc = this.rc;
        clone.pkSeed = this.pkSeed;
        return clone;
    }

    private void genRoundConstants() {
        reset();
        this.update(this.pkSeed, 0, this.pkSeed.length);
        absorbPadding();
        rc = squeeze(20);
        reset();
    }


}
