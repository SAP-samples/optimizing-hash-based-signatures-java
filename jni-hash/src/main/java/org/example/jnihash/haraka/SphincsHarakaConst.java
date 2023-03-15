package org.example.jnihash.haraka;

public class SphincsHarakaConst {

    //round constants, converted to little endian so it complies with intel AES-NI
    public static final int[] roundConstants = {
            0x4c708406, 0xac020e6, 0xf0fec5b2, 0x9d7b8175,
            0xe1b4668b, 0x6ba0f388, 0xa46b0f64, 0x17f7082f,
            0x2dde0234, 0x9884f253, 0x609d02cf, 0x1491029f,
            0xe6ead60e, 0x084f7b2e, 0xafbcf3bb, 0x794f5bfd,
            0xcbb0cfcb, 0x8b447248, 0x1ccdee79, 0x447039be,
            0xeecdea7e, 0xb732906e, 0xed35538d, 0x7b058a2b,
            0x438fc267, 0xd07c2e5e, 0x612741e2, 0x1bef4fda,
            0xb0d92429, 0x07cccaaf, 0xe2fd5f67, 0x3b0bc71f,
            0xf1634dab, 0xe97f86e6, 0xca8fdbec, 0xee65d4b9,
            0x84bf301c, 0x64cdb7d4, 0x4f402a5b, 0x337e03ad,
            0xb90bccb2, 0xbf231794, 0x2e8b0269, 0x098f68d,
            0xa67804fa, 0x72556fde, 0xc89eaa4a, 0x8a2d9d5c,
            0x2b9fb4df, 0x122a776b, 0x2e4ffa0e, 0xd49f1229,
            0x4403a11e, 0x36a249f4, 0xae11d632, 0xee126abb,
            0x884904af, 0x8400054b, 0xc900965f, 0xa6eca89c,
            0xd85e0221, 0x4f9c199d, 0xe3c7a278, 0xec93e527,
            0xf8aa3abf, 0xb7c959a7, 0xcd2e28b9, 0x7301d482,
            0xd706062, 0x17b08661, 0xd9eff237, 0x6b7d3010,
            0xc245ca5a, 0x43043021, 0x5391c281, 0xc69afcf6,
            0x3c972392, 0xbb686b22, 0xe892af2c, 0x3a94d136,
            0x3892bfd3, 0xeb865822, 0x58b9ba6c, 0xb47110e5,
            0xe53c86db, 0x77c6f0ae, 0xddfd3d93, 0x8d12e124,
            0x686260bb, 0x9ca0ebff, 0xe38de483, 0xb11222cb,
            0xdcd34b73, 0x9cd1e4e2, 0x4e1ab92d, 0x7df72bc7,
            0xc347bb43, 0x431b3061, 0xc415144b, 0x4e92b32c,
            0xa875a7db, 0xf6ef07e7, 0xdd31b203, 0x9968eb16,
            0x4b61f36d, 0x7759753c, 0x2235e8e, 0x2c47ca7e,
            0x175aa7cd, 0x777dded6, 0xb9e51b6d, 0xf91786b8,
            0xf0436bec, 0xaae9a86b, 0x9d066c9d, 0x5dee46a9,
            0x50691ecb, 0x2b3357f9, 0x591153a2, 0xc127f33b,
            0x750cee2c, 0x9c61da00, 0x5303ede4, 0xd9d00e60,
            0xa1a5b1f0, 0xab0ce996, 0xbcbabb80, 0x50a3a463,
            0x2b13dae, 0x8829965e, 0x30de0dab, 0x39ca8d93,
            0x388fbb17, 0xba454d5, 0xa8f31488, 0x42b4752e,
            0x5b8abb34, 0xd77f425f, 0x79b7b6ae, 0xf6160a36,
            0x4152f626, 0x3854e5cb, 0x1859ce43, 0xdeafbaff,
            0x549ae94c, 0x6a02f3b9, 0xf79ccaa2, 0x78c99e83,
            0x1aa551ae, 0xbef7df1b, 0x286ec040, 0x35129022,
            0x3c61c1a0, 0x2bd27eba, 0xfbc73c1, 0xcf59a648,
            0x3cc6a75, 0x88822802, 0xfdbdd64a, 0xa19dc5e9};


////////////////////////////////////////////////////////////
////////// IAIK JCE STARTS HERE               //////////////
////////// modified as only a round is needed //////////////
////////////////////////////////////////////////////////////

    /**
     * A single round of AES
     *
     * @param block previous hash in the context of haraka
     * @param K     key, in the context of haraka the message block
     */
    static int[] aesRound(int[] block, int[] K) {
        int x0 = block[0];
        int x1 = block[1];
        int x2 = block[2];
        int x3 = block[3];
        int y0, y1, y2, y3;
        int i = 0;
        y0 = ET0[x0 >>> 24] ^ ET1[(x1 >>> 16) & 0xff];
        y0 ^= ET2[(x2 >>> 8) & 0xff] ^ ET3[x3 & 0xff];
        y0 ^= K[i++];

        y1 = ET0[x1 >>> 24] ^ ET1[(x2 >>> 16) & 0xff];
        y1 ^= ET2[(x3 >>> 8) & 0xff] ^ ET3[x0 & 0xff];
        y1 ^= K[i++];

        y2 = ET0[x2 >>> 24] ^ ET1[(x3 >>> 16) & 0xff];
        y2 ^= ET2[(x0 >>> 8) & 0xff] ^ ET3[x1 & 0xff];
        y2 ^= K[i++];

        y3 = ET0[x3 >>> 24] ^ ET1[(x0 >>> 16) & 0xff];
        y3 ^= ET2[(x1 >>> 8) & 0xff] ^ ET3[x2 & 0xff];
        y3 ^= K[i];

        block[0] = y0;
        block[1] = y1;
        block[2] = y2;
        block[3] = y3;

        return block;
    }

    // 16 permanent tables of 1 kbyte each shared from RawRijndael.
    private static final int[] ET0, ET1, ET2, ET3;

    static {
        ET0 = new int[256];
        ET1 = new int[256];
        ET2 = new int[256];
        ET3 = new int[256];
        initTables();
    }


    private static int ROTR(int x, int amount) {
        return (x >>> (amount & 0x1f)) | (x << (32 - (amount & 0x1f)));
    }

    private static void initTables() {
        logTable = new int[256];
        powTable = new int[256];
        int[] sbox = new int[256];

        for (int i = 0, p = 1; i < 256; i++) {
            powTable[i] = p;
            logTable[p] = i;
            p = p ^ (p << 1) ^ ((p & 0x80) != 0 ? 0x11b : 0);
        }
        logTable[1] = 0;


        for (int i = 0, p, q; i < 256; i++) {
            p = (i != 0) ? powTable[255 - logTable[i]] : 0;
            q = p;

            q = (q >>> 7) | (q << 1);
            p ^= q;

            q = (q >>> 7) | (q << 1);
            p ^= q;

            q = (q >>> 7) | (q << 1);
            p ^= q;

            q = (q >>> 7) | (q << 1);
            p ^= q ^ 0x63;

            p &= 0xff;
            sbox[i] = p;
        }

        for (int i = 0, p, t; i < 256; i++) {
            p = sbox[i];

            t = mult(3, p) | (p << 8) | (p << 16) | (mult(2, p) << 24);
            ET0[i] = t;
            ET1[i] = ROTR(t, 8);
            ET2[i] = ROTR(t, 16);
            ET3[i] = ROTR(t, 24);

        }
        // no longer needed
        logTable = null;
        powTable = null;
    }

    // temporary tables
    private static int[] logTable, powTable;

    private static int mult(int a, int b) {
        if ((a == 0) || (b == 0)) {
            return 0;
        }
        a = logTable[a] + logTable[b];
        if (a < 255) {
            return powTable[a];
        }

        return powTable[a - 255];
    }
}
