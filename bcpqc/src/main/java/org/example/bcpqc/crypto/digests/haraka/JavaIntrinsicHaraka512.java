package org.example.bcpqc.crypto.digests.haraka;

import java.util.Arrays;

public class JavaIntrinsicHaraka512 extends JavaIntrinsicHarakaN {
    public JavaIntrinsicHaraka512(JavaIntrinsicHarakaS harakaS) {
        super(64, harakaS);
    }

    @Override
    protected byte[] permuteAndXor(byte[] msg, byte[] rc, int digestSize) {
        this.harakaS.electronicCodeBook.encrypt(msg, 0, msg.length, this.harakaS.getRCs(), 0);
        return Arrays.copyOf(msg, digestSize);
    }

}
