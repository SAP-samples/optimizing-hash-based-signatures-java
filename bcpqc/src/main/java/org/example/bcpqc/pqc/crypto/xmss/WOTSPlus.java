package org.example.bcpqc.pqc.crypto.xmss;

import org.bouncycastle.util.Arrays;
import org.example.bcpqc.experiments.hashing.HashingProviderProvider;
import org.example.bcpqc.pqc.crypto.xmss.khf.KeyedHashFunctions;

/**
 * WOTS+.
 */
class WOTSPlus {

    /**
     * Randomization functions.
     */
    protected final KeyedHashFunctions khf;
    /**
     * WOTS+ parameters.
     */
    private final WOTSPlusParameters params;
    /**
     * WOTS+ secret key seed.
     */
    private byte[] secretKeySeed;
    /**
     * WOTS+ public seed.
     */
    private byte[] publicSeed;

    /**
     * Constructs a new WOTS+ one-time signature system based on the given WOTS+
     * parameters.
     *
     * @param params Parameters for WOTSPlus object.
     */
    WOTSPlus(WOTSPlusParameters params) {
        super();
        if (params == null) {
            throw new NullPointerException("params == null");
        }

        // Required in getBaseW
        if (params.getWinternitzParameter() != 4 && params.getWinternitzParameter() != 16) {
            throw new IllegalArgumentException("w needs to be 4 or 16");
        }

        this.params = params;
        int n = params.getTreeDigestSize();
        khf = HashingProviderProvider.getHashingProvider().newKHF(params.getTreeDigest(), n);
        secretKeySeed = new byte[n];
        publicSeed = new byte[n];
    }

    /**
     * Import keys to WOTS+ instance.
     *
     * @param secretKeySeed Secret key seed.
     * @param publicSeed    Public seed.
     */
    void importKeys(byte[] secretKeySeed, byte[] publicSeed) {
        if (secretKeySeed == null) {
            throw new NullPointerException("secretKeySeed == null");
        }
        if (secretKeySeed.length != params.getTreeDigestSize()) {
            throw new IllegalArgumentException("size of secretKeySeed needs to be equal to size of digest");
        }
        if (publicSeed == null) {
            throw new NullPointerException("publicSeed == null");
        }
        if (publicSeed.length != params.getTreeDigestSize()) {
            throw new IllegalArgumentException("size of publicSeed needs to be equal to size of digest");
        }
        this.secretKeySeed = secretKeySeed;
        this.publicSeed = publicSeed;
    }

    /**
     * Creates a signature for the n-byte messageDigest.
     *
     * @param messageDigest  Digest to sign.
     * @param otsHashAddress OTS hash address for randomization.
     * @return WOTS+ signature.
     */
    WOTSPlusSignature signDigest(byte[] messageDigest, OTSHashAddress otsHashAddress) {
        if (messageDigest == null) {
            throw new NullPointerException("messageDigest == null");
        }
        if (messageDigest.length != params.getTreeDigestSize()) {
            throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
        }
        if (otsHashAddress == null) {
            throw new NullPointerException("otsHashAddress == null");
        }

        byte[] checksumBytes = this.calculateChecksum(messageDigest);

        /* create signature */
        byte[][] signature = new byte[params.getLen()][];
        for (int i = 0; i < params.getLen(); i++) {
            otsHashAddress = (OTSHashAddress) new OTSHashAddress.Builder()
                    .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
                    .withOTSAddress(otsHashAddress.getOTSAddress()).withChainAddress(i)
                    .withHashAddress(otsHashAddress.getHashAddress()).withKeyAndMask(otsHashAddress.getKeyAndMask())
                    .build();
            signature[i] = chain(expandSecretKeySeed(i), 0, getBaseW(messageDigest, checksumBytes, i), otsHashAddress);
        }
        return new WOTSPlusSignature(params, signature);
    }

    protected byte[] calculateChecksum(byte[] digest) {
        /* create checksum */
        int checksum = 0;
        for (int i = 0; i < params.getLen1(); i++) {
            checksum += params.getWinternitzParameter() - 1 - getBaseW(digest, i);
        }
        int checksumLengthBits = params.getLen2() * params.getLogW();
        checksum <<= (8 - (checksumLengthBits % 8));
        int len2Bytes = (int) Math.ceil((double) checksumLengthBits / 8);
        return XMSSUtil.toBytesBigEndian(checksum, len2Bytes);
    }

    /**
     * Calculates a public key based on digest and signature.
     *
     * @param messageDigest  The digest that was signed.
     * @param signature      Signarure on digest.
     * @param otsHashAddress OTS hash address for randomization.
     * @return WOTS+ public key derived from digest and signature.
     */
    WOTSPlusPublicKeyParameters getPublicKeyFromSignature(byte[] messageDigest, WOTSPlusSignature signature,
                                                          OTSHashAddress otsHashAddress) {
        if (messageDigest == null) {
            throw new NullPointerException("messageDigest == null");
        }
        if (messageDigest.length != params.getTreeDigestSize()) {
            throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
        }
        if (signature == null) {
            throw new NullPointerException("signature == null");
        }
        if (otsHashAddress == null) {
            throw new NullPointerException("otsHashAddress == null");
        }

        byte[] checksumBytes = this.calculateChecksum(messageDigest);

        byte[][] publicKey = new byte[params.getLen()][];
        for (int i = 0; i < params.getLen(); i++) {
            otsHashAddress = (OTSHashAddress) new OTSHashAddress.Builder()
                    .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
                    .withOTSAddress(otsHashAddress.getOTSAddress()).withChainAddress(i)
                    .withHashAddress(otsHashAddress.getHashAddress()).withKeyAndMask(otsHashAddress.getKeyAndMask())
                    .build();
            int s = getBaseW(messageDigest, checksumBytes, i);
            publicKey[i] = chain(signature.toByteArray()[i], s,
                    params.getWinternitzParameter() - 1 - s, otsHashAddress);
        }
        return new WOTSPlusPublicKeyParameters(params, publicKey);
    }

    /**
     * Computes an iteration of F on an n-byte input using outputs of PRF.
     *
     * @param startHash      Starting point.
     * @param startIndex     Start index.
     * @param steps          Steps to take.
     * @param otsHashAddress OTS hash address for randomization.
     * @return Value obtained by iterating F for steps times on input startHash,
     * using the outputs of PRF.
     */
    protected byte[] chain(byte[] startHash, int startIndex, int steps, OTSHashAddress otsHashAddress) {
        int n = params.getTreeDigestSize();
        if (startHash == null) {
            throw new NullPointerException("startHash == null");
        }
        if (startHash.length != n) {
            throw new IllegalArgumentException("startHash needs to be " + n + "bytes");
        }
        if (otsHashAddress == null) {
            throw new NullPointerException("otsHashAddress == null");
        }
        if (otsHashAddress.toByteArray() == null) {
            throw new NullPointerException("otsHashAddress byte array == null");
        }
        if ((startIndex + steps) > params.getWinternitzParameter() - 1) {
            throw new IllegalArgumentException("max chain length must not be greater than w");
        }

        if (steps == 0) {
            return startHash;
        }

        byte[] tmp = chain(startHash, startIndex, steps - 1, otsHashAddress);
        otsHashAddress = (OTSHashAddress) new OTSHashAddress.Builder()
                .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
                .withOTSAddress(otsHashAddress.getOTSAddress()).withChainAddress(otsHashAddress.getChainAddress())
                .withHashAddress(startIndex + steps - 1).withKeyAndMask(0).build();
        byte[] key = khf.PRF(publicSeed, otsHashAddress.toByteArray());
        otsHashAddress = (OTSHashAddress) new OTSHashAddress.Builder()
                .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
                .withOTSAddress(otsHashAddress.getOTSAddress()).withChainAddress(otsHashAddress.getChainAddress())
                .withHashAddress(otsHashAddress.getHashAddress()).withKeyAndMask(1).build();
        byte[] bitmask = khf.PRF(publicSeed, otsHashAddress.toByteArray());
        byte[] tmpMasked = new byte[n];
        for (int i = 0; i < n; i++) {
            tmpMasked[i] = (byte) (tmp[i] ^ bitmask[i]);
        }
        tmp = khf.F(key, tmpMasked);
        return tmp;
    }

    /**
     * Derive WOTS+ secret key for specific index as in XMSS ref impl Andreas
     * Huelsing.
     *
     * @param otsHashAddress one time hash address.
     * @return WOTS+ secret key at index.
     */
    protected byte[] getWOTSPlusSecretKey(byte[] secretKeySeed, OTSHashAddress otsHashAddress) {
        otsHashAddress = (OTSHashAddress) new OTSHashAddress.Builder()
                .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
                .withOTSAddress(otsHashAddress.getOTSAddress()).build();
        return khf.PRF(secretKeySeed, otsHashAddress.toByteArray());
    }

    /**
     * Derive private key at index from secret key seed.
     *
     * @param index Index.
     * @return Private key at index.
     */
    protected byte[] expandSecretKeySeed(int index) {
        if (index < 0 || index >= params.getLen()) {
            throw new IllegalArgumentException("index out of bounds");
        }
        return khf.PRF(secretKeySeed, XMSSUtil.toBytesBigEndian(index, 32));
    }

    /**
     * Getter parameters.
     *
     * @return params.
     */
    protected WOTSPlusParameters getParams() {
        return params;
    }

    /**
     * Getter keyed hash functions.
     *
     * @return keyed hash functions.
     */
    protected KeyedHashFunctions getKhf() {
        return khf;
    }

    /**
     * Getter secret key seed.
     *
     * @return secret key seed.
     */
    protected byte[] getSecretKeySeed() {
        return Arrays.clone(secretKeySeed);
    }

    /**
     * Getter public seed.
     *
     * @return public seed.
     */
    protected byte[] getPublicSeed() {
        return Arrays.clone(publicSeed);
    }

    /**
     * Getter private key.
     *
     * @return WOTS+ private key.
     */
    protected WOTSPlusPrivateKeyParameters getPrivateKey() {
        byte[][] privateKey = new byte[params.getLen()][];
        for (int i = 0; i < privateKey.length; i++) {
            privateKey[i] = expandSecretKeySeed(i);
        }
        return new WOTSPlusPrivateKeyParameters(params, privateKey);
    }

    /**
     * Calculates a new public key based on the state of secretKeySeed,
     * publicSeed and otsHashAddress.
     *
     * @param otsHashAddress OTS hash address for randomization.
     * @return WOTS+ public key.
     */
    WOTSPlusPublicKeyParameters getPublicKey(OTSHashAddress otsHashAddress) {
        if (otsHashAddress == null) {
            throw new NullPointerException("otsHashAddress == null");
        }
        byte[][] publicKey = new byte[params.getLen()][];
        /* derive public key from secretKeySeed */
        for (int i = 0; i < params.getLen(); i++) {
            otsHashAddress = (OTSHashAddress) new OTSHashAddress.Builder()
                    .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
                    .withOTSAddress(otsHashAddress.getOTSAddress()).withChainAddress(i)
                    .withHashAddress(otsHashAddress.getHashAddress()).withKeyAndMask(otsHashAddress.getKeyAndMask())
                    .build();
            publicKey[i] = chain(expandSecretKeySeed(i), 0, params.getWinternitzParameter() - 1, otsHashAddress);
        }
        return new WOTSPlusPublicKeyParameters(params, publicKey);
    }

    protected int getBaseW(byte[] digest, byte[] checksum, int pos) {
        if (pos >= this.params.getLen1()) {
            return getBaseW(checksum, pos - this.params.getLen1());
        }
        return getBaseW(digest, pos);
    }

    protected int getBaseW(byte[] digest, int pos) {
        int w = params.getWinternitzParameter();

        int logW = params.getLogW();
        int blocksPerByte = 8 / logW;

        int i = pos / blocksPerByte;
        int j = blocksPerByte - 1 - (pos % blocksPerByte);

        return (digest[i] >> j * logW) & (w - 1);
    }
}
