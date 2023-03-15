package org.example.bcpqc.pqc.crypto.xmss.khf;

import org.example.bcpqc.pqc.crypto.xmss.XMSSUtil;

import java.security.MessageDigest;

public class MessageDigestKHF extends AbstractDigestKHF {
    private final MessageDigest digest;

    public MessageDigestKHF(MessageDigest digest, int digestSize) {
        super(digestSize);
        this.digest = digest;
    }

    @Override
    protected byte[] coreDigest(int fixedValue, byte[] key, byte[] index) {
        byte[] in = XMSSUtil.toBytesBigEndian(fixedValue, this.paddingSize);
        /* fill first n byte of out buffer */
        digest.update(in, 0, in.length);
        /* add key */
        digest.update(key, 0, key.length);
        /* add index */
        digest.update(index, 0, index.length);


        // Handle SHA-256/192
        if (digestSize < digest.getDigestLength()) {
            byte[] out = new byte[digestSize];
            byte[] buffer = digest.digest();
            System.arraycopy(buffer, 0, out, 0, digestSize);
            return out;
        } else {
            return digest.digest();
        }
    }
}
