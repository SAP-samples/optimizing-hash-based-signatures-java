package org.example.bcpqc.crypto.digests.haraka;

import java.util.Arrays;

public abstract class JavaIntrinsicHarakaN {
    protected final int n;
    protected final JavaIntrinsicHarakaS harakaS;
    protected int ofs = 0;

    protected byte[] msg;

    protected int max = 0;

    protected JavaIntrinsicHarakaN(int n, JavaIntrinsicHarakaS harakaS) {
        this.n = n;
        this.harakaS = harakaS;
        this.msg = new byte[this.n];
    }

    public void update(byte[] bytes, int offset, int length) {
        if (ofs + (length - offset) > n) {
            throw new IllegalArgumentException("Given inout is too long");
        }
        System.arraycopy(bytes, offset, this.msg, ofs, length);
        ofs += length;
        if (ofs > max) {
            max = ofs;
        }
    }

    public void reset() {
        this.ofs = 0;
    }

    public byte[] digest(int digestSize) {
        if (max > ofs) {
            Arrays.fill(msg, ofs, max, (byte) 0);
        }
        max = ofs;

        byte[] r = permuteAndXor(msg, harakaS.getRCs(), digestSize);

        // Avoid further updates before reset
        ofs = n;

        return r;
    }

    protected abstract byte[] permuteAndXor(byte[] msg, byte[] rc, int digestSize);


}
