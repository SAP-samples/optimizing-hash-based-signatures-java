package org.example.bcpqc.jcajce.util;

import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.example.bcpqc.jce.provider.SAPBouncyCastleProvider;

import java.security.Provider;
import java.security.Security;

public class SAPBCJcaJceHelper
        extends ProviderJcaJceHelper {
    private static volatile Provider sapbcProvider;

    private static synchronized Provider getSAPBouncyCastleProvider() {
        final Provider system = Security.getProvider("BC");
        // Avoid using the old, deprecated system BC provider on Android.
        // See: https://android-developers.googleblog.com/2018/03/cryptography-changes-in-android-p.html
        if (system instanceof SAPBouncyCastleProvider) {
            return system;
        } else if (sapbcProvider != null) {
            return sapbcProvider;
        } else {
            sapbcProvider = new SAPBouncyCastleProvider();

            return sapbcProvider;
        }
    }

    public SAPBCJcaJceHelper() {
        super(getSAPBouncyCastleProvider());
    }
}
