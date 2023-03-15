package org.example.bcpqc.pqc.crypto.xmss;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.bouncycastle.crypto.Digest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

public class DigestMessageDigestAdapter implements Digest {
    private MessageDigest md;

    private static boolean correttoLoaded = false;

    private static void initCorretto() {
        if (!correttoLoaded && Security.getProvider(AmazonCorrettoCryptoProvider.PROVIDER_NAME) == null) {
            Security.addProvider(AmazonCorrettoCryptoProvider.INSTANCE);

            AmazonCorrettoCryptoProvider.INSTANCE.assertHealthy();
            correttoLoaded = true;
        }

    }

    public DigestMessageDigestAdapter(MessageDigest md) {
        this.md = md;
    }


    @Override
    public String getAlgorithmName() {
        return md.getAlgorithm();
    }

    @Override
    public int getDigestSize() {
        return md.getDigestLength();
    }

    @Override
    public void update(byte in) {
        md.update(in);
    }

    @Override
    public void update(byte[] in, int inOff, int len) {
        md.update(in, inOff, len);
    }

    @Override
    public int doFinal(byte[] out, int outOff) {
        System.arraycopy(md.digest(), outOff, out, 0, (md.getDigestLength() - outOff));
        return 0;
    }

    @Override
    public void reset() {
        md.reset();
    }

    public static Digest correttoSha256() {
        try {
            initCorretto();
            return new DigestMessageDigestAdapter(MessageDigest.getInstance("SHA-256", AmazonCorrettoCryptoProvider.PROVIDER_NAME));
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    public static Digest sunSha256() {
        try {
            return new DigestMessageDigestAdapter(MessageDigest.getInstance("SHA-256", "SUN"));
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }


    public static Digest correttoSha512() {
        try {
            initCorretto();
            return new DigestMessageDigestAdapter(MessageDigest.getInstance("SHA-512", AmazonCorrettoCryptoProvider.PROVIDER_NAME));
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    public static Digest sunSha512() {
        try {
            return new DigestMessageDigestAdapter(MessageDigest.getInstance("SHA-512", "SUN"));
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

}
