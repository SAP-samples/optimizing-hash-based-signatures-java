package org.example.bcpqc.pqc.crypto.lms;

import junit.framework.TestCase;

import java.util.Arrays;

public class TypeTests
        extends TestCase {

    /**
     * Get instance methods are expected to return the instance passed to them if it is the same type.
     *
     * @throws Exception
     */
    public void testTypeForType()
            throws Exception {
        LMSSignature dummySig = new LMSSignature(0, null, null, null);

        {
            Object o = new HSSPrivateKeyParameters(0,
                    Arrays.asList(new LMSPrivateKeyParameters(LMSigParameters.lms_sha256_m32_h5, null, 0, null, 0, new byte[32])),
                    Arrays.asList(dummySig), 1, 2);
            assert (o == HSSPrivateKeyParameters.getInstance(o));
        }

        {
            Object o = new HSSPublicKeyParameters(0, null);
            assert (o == HSSPublicKeyParameters.getInstance(o));
        }

        {
            Object o = new HSSSignature(0, null, null);
            assert (o == HSSSignature.getInstance(o, 0));
        }

        {
            Object o = new LMOtsPublicKey(null, null, 0, null);
            assert (o == LMOtsPublicKey.getInstance(o));
        }

        {
            Object o = new LMOtsSignature(null, null, null);
            assert (o == LMOtsSignature.getInstance(o));
        }

        {
            Object o = new LMSPrivateKeyParameters(LMSigParameters.lms_sha256_m32_h5, null, 0, null, 0, null);
            assert (o == LMSPrivateKeyParameters.getInstance(o));
        }

        {
            Object o = new LMSPublicKeyParameters(null, null, null, null);
            assert (o == LMSPublicKeyParameters.getInstance(o));
        }

        {
            Object o = new LMSSignature(0, null, null, null);
            assert (o == LMSSignature.getInstance(o));
        }


    }
}
