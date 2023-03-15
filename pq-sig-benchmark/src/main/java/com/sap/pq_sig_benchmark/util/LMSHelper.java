package com.sap.pq_sig_benchmark.util;

import org.example.bcpqc.pqc.crypto.lms.LMOtsParameters;
import org.example.bcpqc.pqc.crypto.lms.LMSigParameters;
import org.example.bcpqc.pqc.jcajce.spec.LMSKeyGenParameterSpec;

public class LMSHelper {
    public static LMSKeyGenParameterSpec buildKeyGenParameterSpec(String sigParameterString) throws NoSuchFieldException, IllegalAccessException {
        LMSigParameters sigParameters = (LMSigParameters) LMSigParameters.class.getField(sigParameterString).get(null);

        LMOtsParameters otsParameters;

        // We use only w = 4 to reduce the amount of parameter sets to test. w is fixed because we understand the impact
        // the Winternitz param has on run times. w = 4 is chosen because XMSS also uses (only) this Winternitz
        // parameter.
        if (sigParameterString.contains("sha256_m32")) {
            otsParameters = LMOtsParameters.sha256_n32_w4;
        } else if (sigParameterString.contains("sha256_m24")) {
            otsParameters = LMOtsParameters.sha256_n24_w4;
        } else if (sigParameterString.contains("shake_m32")) {
            otsParameters = LMOtsParameters.shake_n32_w4;
        } else if (sigParameterString.contains("shake_m24")) {
            otsParameters = LMOtsParameters.shake_n24_w4;
        } else {
            throw new IllegalArgumentException();
        }
        return new LMSKeyGenParameterSpec(sigParameters, otsParameters);
    }
}
