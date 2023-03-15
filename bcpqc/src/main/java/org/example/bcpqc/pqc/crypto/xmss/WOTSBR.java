package org.example.bcpqc.pqc.crypto.xmss;

public class WOTSBR extends WOTSPlus {

    private final WOTSBRParameters wotsBRParams;

    public WOTSBR(WOTSBRParameters params) {
        super(params);
        this.wotsBRParams = params;
    }


    public WOTSBRSignature signMessage(byte[] keyHMsg, byte[] msg, OTSHashAddress otsHashAddress) {
        byte[] ctr_bytes = new byte[8];
        byte[] digest = null;
        byte[] maxDigest = null;
        int maxSum = -1;
        long maxCtr = -1;

        Object state = khf.HMsg_consumeMessage(keyHMsg, msg);

        int w = wotsBRParams.getWinternitzParameter();
        int logW = wotsBRParams.getLogW();
        int blocksPerByte = 8 / logW;

        // Constants for check sum calculation
        int checksumLengthBits = wotsBRParams.getLen2() * wotsBRParams.getLogW();
        int len2Bytes = (int) Math.ceil((double) checksumLengthBits / 8);
        int unusedBitsOnes = (1 << wotsBRParams.getChecksumUnusedBits()) - 1;
        // Only works for w = 4 or w = 16 (like calculateChecksum)
        int onePaddingMask = unusedBitsOnes << (8 - wotsBRParams.getChecksumUnusedBits());

        for (long ctr = 0; ctr < wotsBRParams.getIterationsR(); ctr++) {
            XMSSUtil.longToBigEndian(ctr, ctr_bytes, 0);
            digest = khf.HMsg_counter(state, ctr_bytes);

            int sum = 0;


            if (!wotsBRParams.isIncludeChecksum()) {
                for (int j = 0; j < wotsBRParams.getLen1(); j++) {
                    // GetBaseW
                    int i = j / blocksPerByte;
                    int j1 = blocksPerByte - 1 - (j % blocksPerByte);

                    sum += (digest[i] >> j1 * logW) & (w - 1);
                }
            } else {
                int checksum = 0;

                for (int i = 0; i < wotsBRParams.getLen1(); i++) {
                    // GetBaseW
                    int i1 = i / blocksPerByte;
                    int j = blocksPerByte - 1 - (i % blocksPerByte);

                    int baseW = (digest[i1] >> j * logW) & (w - 1);
                    sum += baseW;
                    checksum += wotsBRParams.getWinternitzParameter() - 1 - baseW;
                }

                checksum <<= (8 - (checksumLengthBits % 8));
                byte[] checksumBytes = XMSSUtil.toBytesBigEndian(checksum, len2Bytes);

                if (wotsBRParams.isUseOnePadding()) {
                    checksumBytes[0] ^= onePaddingMask;
                }

                for (int j = 0; j < this.wotsBRParams.getLen2(); j++) {
                    // GetBaseW
                    int i = j / blocksPerByte;
                    int j1 = blocksPerByte - 1 - (j % blocksPerByte);

                    sum += (checksumBytes[i] >> j1 * logW) & (w - 1);
                }

            }

            if (sum > maxSum) {
                maxSum = sum;
                maxDigest = digest;
                maxCtr = ctr;
            }
        }

        WOTSPlusSignature sig = super.signDigest(maxDigest, otsHashAddress);
        return new WOTSBRSignature(wotsBRParams, sig.toByteArray(), maxCtr, maxSum);
    }

    @Override
    protected byte[] calculateChecksum(byte[] digest) {
        if (wotsBRParams.isUseOnePadding()) {
            return this.calculateOnePaddedChecksum(digest);
        }
        return super.calculateChecksum(digest);
    }

    private byte[] calculateOnePaddedChecksum(byte[] digest) {
        int requiredBits = (int) Math.ceil(Math.log(wotsBRParams.getLen1() * (wotsBRParams.getWinternitzParameter() - 1)) / Math.log(2));

        int allocatedBits = wotsBRParams.getLen2() * wotsBRParams.getLogW();
        int unusedBits = allocatedBits - requiredBits;

        byte[] checksum = super.calculateChecksum(digest);

        // Only works for w = 4 or w = 16 (like calculateChecksum)
        int unusedBitsOnes = (1 << unusedBits) - 1;
        checksum[0] ^= unusedBitsOnes << (8 - unusedBits);
        return checksum;
    }


    @Override
    WOTSPlusSignature signDigest(byte[] messageDigest, OTSHashAddress otsHashAddress) {
        throw new RuntimeException("Not supported");
    }

    public WOTSPlusPublicKeyParameters getPublicKeyFromSignatureAndMessage(byte[] keyHMsg, byte[] msg, WOTSBRSignature wotsPlusCtrSignature, OTSHashAddress otsAddress) {
        byte[] in = new byte[msg.length + 8];
        System.arraycopy(msg, 0, in, 0, msg.length);
        XMSSUtil.longToBigEndian(wotsPlusCtrSignature.getCtr(), in, msg.length);

        byte[] digest = khf.HMsg(keyHMsg, in);

        return getPublicKeyFromSignature(digest, wotsPlusCtrSignature, otsAddress);

    }
}
