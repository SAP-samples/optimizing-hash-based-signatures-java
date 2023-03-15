package org.example.bcpqc.pqc.crypto.xmss;

import org.bouncycastle.util.Pack;

/**
 * OTS hash address.
 */
public final class OTSHashAddress
        extends XMSSAddress {

    private static final int TYPE = 0x00;

    private final int otsAddress;
    private final int chainAddress;
    private final int hashAddress;

    private OTSHashAddress(Builder builder) {
        super(builder);
        otsAddress = builder.otsAddress;
        chainAddress = builder.chainAddress;
        hashAddress = builder.hashAddress;
    }

    public byte[] toByteArray() {
        byte[] byteRepresentation = super.toByteArray();
        Pack.intToBigEndian(otsAddress, byteRepresentation, 16);
        Pack.intToBigEndian(chainAddress, byteRepresentation, 20);
        Pack.intToBigEndian(hashAddress, byteRepresentation, 24);
        return byteRepresentation;
    }

    public int getOTSAddress() {
        return otsAddress;
    }

    public int getChainAddress() {
        return chainAddress;
    }

    public int getHashAddress() {
        return hashAddress;
    }

    public static class Builder
            extends XMSSAddress.Builder<Builder> {

        /* optional */
        private int otsAddress = 0;
        private int chainAddress = 0;
        private int hashAddress = 0;

        public Builder() {
            super(TYPE);
        }

        public Builder withOTSAddress(int val) {
            otsAddress = val;
            return this;
        }

        public Builder withChainAddress(int val) {
            chainAddress = val;
            return this;
        }

        public Builder withHashAddress(int val) {
            hashAddress = val;
            return this;
        }

        public XMSSAddress build() {
            return new OTSHashAddress(this);
        }

        public Builder getThis() {
            return this;
        }
    }
}
