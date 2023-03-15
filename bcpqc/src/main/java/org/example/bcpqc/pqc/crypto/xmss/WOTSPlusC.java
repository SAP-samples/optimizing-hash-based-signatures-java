package org.example.bcpqc.pqc.crypto.xmss;

public class WOTSPlusC extends WOTSPlus {
    private static final long MAX_ITERATIONS = 10000000000L;
    private final WOTSPlusCParameters wotsPlusCParameters;

    public WOTSPlusC(WOTSPlusCParameters params) {
        super(params);
        this.wotsPlusCParameters = params;
    }

    public WOTSPlusCtrSignature signMessage(byte[] keyHMsg, byte[] msg, OTSHashAddress otsHashAddress) {
        byte[] ctr_bytes = new byte[8];
        long ctr = 0;
        byte[] digest = null;
        boolean found = false;

        Object state = khf.HMsg_consumeMessage(keyHMsg, msg);

        while (ctr < MAX_ITERATIONS) {
            XMSSUtil.longToBigEndian(ctr, ctr_bytes, 0);
            digest = khf.HMsg_counter(state, ctr_bytes);

            if (isValid(digest)) {
                found = true;
                break;
            }
            ctr++;
        }

        if (!found) {
            return null;
        }

        byte[][] signature = new byte[wotsPlusCParameters.getLen()][];
        for (int i = 0; i < wotsPlusCParameters.getLen(); i++) {
            otsHashAddress = (OTSHashAddress) new OTSHashAddress.Builder()
                    .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
                    .withOTSAddress(otsHashAddress.getOTSAddress()).withChainAddress(i)
                    .withHashAddress(otsHashAddress.getHashAddress()).withKeyAndMask(otsHashAddress.getKeyAndMask())
                    .build();
            signature[i] = chain(expandSecretKeySeed(i), 0, this.getBaseW(digest, wotsPlusCParameters.getZ() + i), otsHashAddress);
        }

        return new WOTSPlusCtrSignature(wotsPlusCParameters, signature, ctr);
    }

    WOTSPlusPublicKeyParameters getPublicKeyFromSignatureAndMessage(byte[] keyHMsg, byte[] msg, WOTSPlusSignature signature, OTSHashAddress otsHashAddress) {
        if (!(signature instanceof WOTSPlusCtrSignature wotsPlusCtrSignature)) {
            throw new IllegalArgumentException("Singature must be a WOTSPlusCSignature");
        }

        byte[] in = new byte[msg.length + 8];
        System.arraycopy(msg, 0, in, 0, msg.length);
        XMSSUtil.longToBigEndian(wotsPlusCtrSignature.getCtr(), in, msg.length);

        byte[] digest = khf.HMsg(keyHMsg, in);

        if (!isValid(digest)) {
            return null;
        }
        byte[][] publicKey = new byte[wotsPlusCParameters.getLen()][];
        for (int i = 0; i < wotsPlusCParameters.getLen(); i++) {
            otsHashAddress = (OTSHashAddress) new OTSHashAddress.Builder()
                    .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
                    .withOTSAddress(otsHashAddress.getOTSAddress()).withChainAddress(i)
                    .withHashAddress(otsHashAddress.getHashAddress()).withKeyAndMask(otsHashAddress.getKeyAndMask())
                    .build();
            int s = this.getBaseW(digest, wotsPlusCParameters.getZ() + i);
            publicKey[i] = chain(signature.toByteArray()[i], s, wotsPlusCParameters.getWinternitzParameter() - 1 - s, otsHashAddress);
        }

        return new WOTSPlusPublicKeyParameters(wotsPlusCParameters, publicKey);
    }

    @Override
    WOTSPlusSignature signDigest(byte[] messageDigest, OTSHashAddress otsHashAddress) {
        throw new RuntimeException("Not implemented");
    }

    @Override
    WOTSPlusPublicKeyParameters getPublicKeyFromSignature(byte[] messageDigest, WOTSPlusSignature signature, OTSHashAddress otsHashAddress) {
        throw new RuntimeException("Not implemented");
    }

    private boolean isValid(byte[] messageDigest) {
        if (messageDigest == null) {
            throw new NullPointerException("msg == null");
        }
        int w = wotsPlusCParameters.getWinternitzParameter();
        if (w != 4 && w != 16) {
            throw new IllegalArgumentException("w needs to be 4 or 16");
        }

        int logW = wotsPlusCParameters.getLogW();
        int blocksPerByte = 8 / logW;
        int sum = 0;


        for (int x = 0; x < this.wotsPlusCParameters.getZ(); x++) {
            int i = x / blocksPerByte;
            int j = x % blocksPerByte;

            int b = (messageDigest[i] >> j) & (w - 1);
            if (b != 0) {
                return false;
            }
        }

        for (int x = this.wotsPlusCParameters.getZ(); x < (messageDigest.length * blocksPerByte); x++) {
            int i = x / blocksPerByte;
            int j = x % blocksPerByte;

            sum += (messageDigest[i] >> (j * logW)) & (w - 1);
        }

        return sum == this.wotsPlusCParameters.getS();
    }

}
