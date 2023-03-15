package org.example.bcpqc.pqc.crypto.xmss.khf;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Xof;
import org.example.bcpqc.pqc.crypto.xmss.XMSSUtil;

public class BCDigestKHF extends AbstractDigestKHF {
    private Digest digest;

    public BCDigestKHF(Digest digest, int digestSize) {
        super(digestSize);
        if (digest == null) {
            throw new IllegalArgumentException("digest == null");
        }
        this.digest = digest;
    }

    @Override
    public byte[] coreDigest(int fixedValue, byte[] key, byte[] index) {
        byte[] in = XMSSUtil.toBytesBigEndian(fixedValue, this.paddingSize);
        /* fill first n byte of out buffer */
        digest.update(in, 0, in.length);
        /* add key */
        digest.update(key, 0, key.length);
        /* add index */
        digest.update(index, 0, index.length);

        byte[] out = new byte[digestSize];
        if (digest instanceof Xof) {
            ((Xof) digest).doFinal(out, 0, digestSize);
        }
        // Handle SHA-256/192
        else if (digestSize < digest.getDigestSize()) {
            byte[] buffer = new byte[digest.getDigestSize()];
            digest.doFinal(buffer, 0);
            System.arraycopy(buffer, 0, out, 0, digestSize);
        } else {
            digest.doFinal(out, 0);
        }
        return out;
    }
}
