package org.example.jnihash;

import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;

public class JniShakeTest {
    final byte data1[] = {0, 1, 2, 3, 4, 5, 1, 2, 3, 4, 4, 5, 5, 2};
    final byte data2[] = {0, 1, 2, 5, 5, 2,  3, 4, 5, 1, 2, 3, 4, 4, 0, 0, 0, 0, 3};


    @Test
    public void testJniShake(){
        JniShake s = new JniShake();

        long ctx1 = s.shake256_context();

        s.shake256_update(ctx1, data1, 0, data1.length);

        byte[] md = new byte[32];
        s.shake256_doFinal(ctx1, 32, md, 0);

        //s.shake256_free(ctx1);

        Xof d = new SHAKEDigest(256);
        d.update(data1, 0, data1.length);
        byte[] md_bc = new byte[32];
        d.doOutput(md_bc, 0, 32);

        assertArrayEquals(md_bc, md);
    }

    @Test
    public void testMultipleJniShake() {
        JniShake s = new JniShake();
        long ctx1 = s.shake256_context();

        s.shake256_update(ctx1, data1, 0, data1.length);

        long ctx2 = s.shake256_context();

        s.shake256_update(ctx1, data1, 0, data1.length);
        s.shake256_update(ctx2, data1, 0, data1.length);
        s.shake256_update(ctx2, data1, 0, data1.length);
        s.shake256_update(ctx2, data2, 0, data2.length);
        s.shake256_update(ctx1, data2, 0, data2.length);

        byte[] md1 = new byte[32];
        byte[] md2 = new byte[32];

        s.shake256_doFinal(ctx1, 32, md1, 0);
        s.shake256_doFinal(ctx2, 32, md2, 0);
        //s.shake256_free(ctx1);
        //s.shake256_free(ctx2);


        Xof d = new SHAKEDigest(256);
        d.update(data1, 0, data1.length);
        d.update(data1, 0, data1.length);
        d.update(data2, 0, data2.length);
        byte bc_md[] = new byte[32];
        d.doOutput(bc_md, 0, 32);

        assertArrayEquals(bc_md, md1);
        assertArrayEquals(bc_md, md2);
    }

    @Test
    public void testJniShakeDigest(){
        JniShake256Digest j = new JniShake256Digest();

        j.update(data1, 0, data1.length);
        j.update(data2, 0, data2.length);

        byte[] md = new byte[24];
        j.doFinal(md, 0, 24);

        Xof d = new SHAKEDigest(256);
        d.update(data1, 0, data1.length);
        d.update(data2, 0, data2.length);
        byte bc_md[] = new byte[24];
        d.doFinal(bc_md, 0, 24);

        assertArrayEquals(bc_md, md);


        j.update(data2, 0, data2.length);
        j.doFinal(md, 0, 24);

        d.update(data2, 0, data2.length);
        d.doFinal(bc_md, 0, 24);

        assertArrayEquals(bc_md, md);
    }
}
