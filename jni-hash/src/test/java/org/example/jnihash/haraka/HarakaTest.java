package org.example.jnihash.haraka;

import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;


public class HarakaTest {

    @Test
    public void HarakaProvider512Test() throws Exception {
        SphincsHaraka512 md = new SphincsHaraka512AESNI();
        byte[] input = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};
        md.update(input, 0, 64);
        byte[] result = md.digest();
        byte[] output = {(byte) 0xbe, 0x7f, 0x72, 0x3b, 0x4e, (byte) 0x80, (byte) 0xa9, (byte) 0x98, 0x13, (byte) 0xb2, (byte) 0x92, 0x28, 0x7f, 0x30, 0x6f, 0x62, 0x5a, 0x6d, 0x57, 0x33, 0x1c, (byte) 0xae, 0x5f, 0x34, (byte) 0xdd, (byte) 0x92, 0x77, (byte) 0xb0, (byte) 0x94, 0x5b, (byte) 0xe2, (byte) 0xaa};
        assertArrayEquals(output, result);
    }

    @Test
    public void Haraka256ProviderTest() throws Exception {
        SphincsHaraka256 md = new SphincsHaraka256AESNI();
        byte[] input = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
        md.update(input, 0, 32);
        byte[] result = md.digest();
        byte[] output = {(byte) 0x80, 0x27, (byte) 0xcc, (byte) 0xb8, 0x79, 0x49, 0x77, 0x4b, 0x78, (byte) 0xd0, 0x54, 0x5f, (byte) 0xb7, 0x2b, (byte) 0xf7, 0x0c,
                0x69, 0x5c, 0x2a, 0x09, 0x23, (byte) 0xcb, (byte) 0xd4, 0x7b, (byte) 0xba, 0x11, 0x59, (byte) 0xef, (byte) 0xbf, 0x2b, 0x2c, 0x1c};
        assertArrayEquals(output, result);

    }

    @Test(expected = IndexOutOfBoundsException.class)
    public void Haraka256FalseLength() throws Exception {
        SphincsHaraka256 md = new SphincsHaraka256Soft();
        byte[] input = {0x0, 0x1, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
        //one byte too short
        md.update(input, 0, 32);
        byte[] result = md.digest();
        assertArrayEquals(null, result);
    }

    @Test(expected = IndexOutOfBoundsException.class)
    public void Haraka512FalseLength() throws Exception {
        SphincsHaraka512 md = new SphincsHaraka512Soft();
        byte[] input = {0x0, 0x1, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
        md.update(input, 0, 32);
        byte[] result = md.digest();
        assertArrayEquals(null, result);
    }

    /*
    @Test
    public void HarakaSTest() throws Exception {
        SphincsHarakaS h = new SphincsHarakaS();
        byte[] pk = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        h.init(pk, null);
        byte[] input = new byte[64];
        for (byte i = 0; i < 64; i++) input[i] = i;
        h.update(input, 0, 64);
        input = h.digest(64 * 8);
        for (int i = 0; i < 64; i++) System.out.print(String.format("%02x", input[i]));
        // test vector without initialization
        //assertEquals("cfbc92bc9b22ec2dd8245e3f7335083551a3c22754d45a2939e58682971989999d75c22d9fe41f831d55cb05220baf98f8649d5b7aeef2f0b3b8b550573c8eab", ByteUtils.bytesToHex(input));
        assertEquals("83a066f693ed85356bbf21727e5ab3b22a755b226105fd8eea00de9562a011416bde87ffbd4e14ea11f58eb83a8de3f28f8e9bd79d7b1db8294202d33a9f6228", ByteUtils.bytesToHex(input));
    }

    @Test
    public void HarakaSTestPK() throws Exception {
        SphincsHarakaSSoft h = new SphincsHarakaSSoft();
        byte[] pk = new byte[64];
        h.init(pk, pk);
        byte[] input = new byte[64];
        for (byte i = 0; i < 64; i++) input[i] = i;
        h.update(input, 0, 64);
        input = h.digest(64 * 8);
        for (int i = 0; i < 64; i++) System.out.print(String.format("%02x", input[i]));
        assertEquals("d8782507f8c85c312fff80225fa9163c1804942f6980f9ae94125bc097029f440e025e1472e6c8b2ab6cdfd26528e762d7a39a926b1244a324f0454f6fc4d02d",ByteUtils.bytesToHex(input));
    }
     */

}
