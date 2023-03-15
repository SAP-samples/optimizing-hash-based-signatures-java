package org.example.bcpqc.pqc.crypto.lms.hash;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public interface LMSHash {
    void treeLeaf(byte[] I, int r, byte[] data, byte[] out);

    void treeIntermediate(byte[] I, int r, byte[] d1, byte[] d2, byte[] out);

    void otsChain(byte[] I, int q, int i, int j, byte[] data, byte[] out);
}
