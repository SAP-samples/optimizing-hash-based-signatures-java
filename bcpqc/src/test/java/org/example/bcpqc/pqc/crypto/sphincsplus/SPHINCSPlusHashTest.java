package org.example.bcpqc.pqc.crypto.sphincsplus;

import junit.framework.TestCase;
import org.bouncycastle.util.encoders.Hex;

public class SPHINCSPlusHashTest extends TestCase {
    private void testSha2Engine(SPHINCSPlusEngine engine) {
        byte[] pkSeed = new byte[engine.N];
        pkSeed[0] = 1;
        pkSeed[pkSeed.length - 1] = 2;
        engine.init(pkSeed);

        ADRS adrs = new ADRS();
        adrs.setType(42);

        byte[] m1 = new byte[engine.N];
        m1[0] = 3;
        m1[m1.length - 1] = 4;

        byte[] m2 = new byte[engine.N];
        m2[0] = 5;
        m2[m2.length - 1] = 6;

        {
            // F
            byte[] out = engine.F(pkSeed, adrs, m1);
            assertEquals("aae569f3b56f87844596cc8c3e04e049", Hex.toHexString(out));
        }

        {
            // H
            byte[] out = engine.H(pkSeed, adrs, m1, m2);
            assertEquals("d11331fe3efbb2eeb25aa49415bff65c", Hex.toHexString(out));
        }

        {
            // PRF
            byte[] prfSeed = new byte[engine.N];
            prfSeed[0] = 7;
            prfSeed[prfSeed.length - 1] = 8;

            byte[] out = engine.PRF(pkSeed, prfSeed, adrs);
            assertEquals("8a54bf3932faf45a93d19ada9f3b6228", Hex.toHexString(out));
        }

        {
            // PRF_msg
            byte[] sk_prf = new byte[engine.N];
            sk_prf[0] = 9;
            sk_prf[sk_prf.length - 1] = 10;

            byte[] optRand = new byte[engine.N];
            optRand[0] = 11;
            optRand[optRand.length - 1] = 12;

            byte[] msg = new byte[1337];
            msg[0] = 13;
            msg[msg.length - 1] = 14;

            byte[] out = engine.PRF_msg(sk_prf, optRand, msg);
            assertEquals("b65fb291b384ba32864890806dc9277a", Hex.toHexString(out));
        }

        {
            // H_msg
            byte[] R = new byte[engine.N];
            R[0] = 15;
            R[R.length - 1] = 16;

            byte[] pkRoot = new byte[engine.N];
            pkRoot[0] = 17;
            pkRoot[pkRoot.length - 1] = 18;

            byte[] msg = new byte[1336];
            msg[0] = 19;
            msg[msg.length - 1] = 20;

            IndexedDigest out = engine.H_msg(R, pkSeed, pkRoot, msg);
            assertEquals("1d16ceda8cfb2f5bc4715274ce59de54fc1ccd0b9254948a4b", Hex.toHexString(out.digest));
        }
    }


    private void testShake256Engine(SPHINCSPlusEngine engine) {
        byte[] pkSeed = new byte[engine.N];
        pkSeed[0] = 1;
        pkSeed[pkSeed.length - 1] = 2;
        engine.init(pkSeed);

        ADRS adrs = new ADRS();
        adrs.setType(42);

        byte[] m1 = new byte[engine.N];
        m1[0] = 3;
        m1[m1.length - 1] = 4;

        byte[] m2 = new byte[engine.N];
        m2[0] = 5;
        m2[m2.length - 1] = 6;

        {
            // F
            byte[] out = engine.F(pkSeed, adrs, m1);
            assertEquals("dc337fa36e3c758d00478b1916de8e7e", Hex.toHexString(out));
        }

        {
            // H
            byte[] out = engine.H(pkSeed, adrs, m1, m2);
            assertEquals("84463b616eb6131d0aa3cb825c61e69d", Hex.toHexString(out));
        }

        {
            // PRF
            byte[] prfSeed = new byte[engine.N];
            prfSeed[0] = 7;
            prfSeed[prfSeed.length - 1] = 8;

            byte[] out = engine.PRF(pkSeed, prfSeed, adrs);
            assertEquals("d93f09d5a9e0881dad05dae13ef09d75", Hex.toHexString(out));
        }

        {
            // PRF_msg
            byte[] sk_prf = new byte[engine.N];
            sk_prf[0] = 9;
            sk_prf[sk_prf.length - 1] = 10;

            byte[] optRand = new byte[engine.N];
            optRand[0] = 11;
            optRand[optRand.length - 1] = 12;

            byte[] msg = new byte[1337];
            msg[0] = 13;
            msg[msg.length - 1] = 14;

            byte[] out = engine.PRF_msg(sk_prf, optRand, msg);
            assertEquals("6e0c4590a90a98075f4cbd9457b9fca6", Hex.toHexString(out));
        }

        {
            // H_msg
            byte[] R = new byte[engine.N];
            R[0] = 15;
            R[R.length - 1] = 16;

            byte[] pkRoot = new byte[engine.N];
            pkRoot[0] = 17;
            pkRoot[pkRoot.length - 1] = 18;

            byte[] msg = new byte[1336];
            msg[0] = 19;
            msg[msg.length - 1] = 20;

            IndexedDigest out = engine.H_msg(R, pkSeed, pkRoot, msg);
            assertEquals("2c5d715d061593fb8e7702358ab6b378f7473e1bdfeb518a1c", Hex.toHexString(out.digest));
        }
    }

    private void testHarakaSEngine(SPHINCSPlusEngine engine) {
        byte[] pkSeed = new byte[engine.N];
        pkSeed[0] = 1;
        pkSeed[pkSeed.length - 1] = 2;
        engine.init(pkSeed);

        ADRS adrs = new ADRS();
        adrs.setType(42);

        byte[] m1 = new byte[engine.N];
        m1[0] = 3;
        m1[m1.length - 1] = 4;

        byte[] m2 = new byte[engine.N];
        m2[0] = 5;
        m2[m2.length - 1] = 6;

        {
            // F
            byte[] out = engine.F(pkSeed, adrs, m1);
            assertEquals("04060af8b1d74e5f7b83012b14e1f8ae", Hex.toHexString(out));
        }

        {
            // H
            byte[] out = engine.H(pkSeed, adrs, m1, m2);
            assertEquals("9c9262423c529533ca3796dcfb179e31", Hex.toHexString(out));
        }

        {
            // PRF
            byte[] prfSeed = new byte[engine.N];
            prfSeed[0] = 7;
            prfSeed[prfSeed.length - 1] = 8;

            byte[] out = engine.PRF(pkSeed, prfSeed, adrs);
            assertEquals("ac97d775766f50760a59be61e5bac98e", Hex.toHexString(out));
        }

        {
            // PRF_msg
            byte[] sk_prf = new byte[engine.N];
            sk_prf[0] = 9;
            sk_prf[sk_prf.length - 1] = 10;

            byte[] optRand = new byte[engine.N];
            optRand[0] = 11;
            optRand[optRand.length - 1] = 12;

            byte[] msg = new byte[1337];
            msg[0] = 13;
            msg[msg.length - 1] = 14;

            byte[] out = engine.PRF_msg(sk_prf, optRand, msg);
            assertEquals("aef63b5e407702aa30d75167b6650ad4", Hex.toHexString(out));
        }

        {
            // H_msg
            byte[] R = new byte[engine.N];
            R[0] = 15;
            R[R.length - 1] = 16;

            byte[] pkRoot = new byte[engine.N];
            pkRoot[0] = 17;
            pkRoot[pkRoot.length - 1] = 18;

            byte[] msg = new byte[1336];
            msg[0] = 19;
            msg[msg.length - 1] = 20;

            IndexedDigest out = engine.H_msg(R, pkSeed, pkRoot, msg);
            assertEquals("d8946f06ee63ea23215af21cb45b6d41e2f1231be7e4061cf5", Hex.toHexString(out.digest));
        }
    }


    public void testBCSha2Engine() {
        SPHINCSPlusEngine engine = new BCSha2Engine(true, 16, 16, 22, 6, 33, 66);
        testSha2Engine(engine);
    }

    public void testJavaSha2Engine() {
        SPHINCSPlusEngine engine = new JavaSha2Engine(true, 16, 16, 22, 6, 33, 66);
        testSha2Engine(engine);
    }

    public void testBCShake256Engine() {
        SPHINCSPlusEngine engine = new BCShake256Engine(true, 16, 16, 22, 6, 33, 66);
        testShake256Engine(engine);
    }

    public void testJavaShake256Engine() {
        SPHINCSPlusEngine engine = new JavaShake256Engine(true, 16, 16, 22, 6, 33, 66);
        testShake256Engine(engine);
    }


    public void testJNIShake256Engine() {
        SPHINCSPlusEngine engine = new JNIShake256Engine(true, 16, 16, 22, 6, 33, 66);
        testShake256Engine(engine);
    }

    public void testBCHarakaSEngine() {
        SPHINCSPlusEngine engine = new BCHarakaSEngine(true, 16, 16, 22, 6, 33, 66);
        testHarakaSEngine(engine);
    }

    public void testJniHarakaSEngine() {
        SPHINCSPlusEngine engine = new JniHarakaSEngine(true, 16, 16, 22, 6, 33, 66);
        testHarakaSEngine(engine);
    }

    public void testJavaHarakaSEngine() {
        SPHINCSPlusEngine engine = new JavaHarakaSEngine(true, 16, 16, 22, 6, 33, 66);
        testHarakaSEngine(engine);
    }


}
