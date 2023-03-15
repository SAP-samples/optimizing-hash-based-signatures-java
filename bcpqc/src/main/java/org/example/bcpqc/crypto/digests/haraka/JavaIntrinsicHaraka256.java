package org.example.bcpqc.crypto.digests.haraka;

import java.util.Arrays;

public class JavaIntrinsicHaraka256 extends JavaIntrinsicHarakaN {
    public JavaIntrinsicHaraka256(JavaIntrinsicHarakaS harakaS) {
        super(32, harakaS);
    }

    @Override
    protected byte[] permuteAndXor(byte[] msg, byte[] rc, int digestSize) {
        harakaS.aesCrypt.encryptBlock(msg, 0, rc, 0);

        return Arrays.copyOf(msg, digestSize);
    }
}
