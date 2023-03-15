package org.example.bcpqc.pqc.asn1;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * XMMSMTKeyParams
 * <pre>
 *     XMMSMTKeyParams ::= SEQUENCE {
 *         version INTEGER -- 0
 *         height INTEGER
 *         layers INTEGER
 *         treeDigest AlgorithmIdentifier
 * }
 * </pre>
 */
public class XMSSMTKeyParams
        extends ASN1Object {
    private final ASN1Integer version;
    private final int height;
    private final int layers;
    private final AlgorithmIdentifier treeDigest;

    public int getTreeDigestSize() {
        return treeDigestSize;
    }

    private final int treeDigestSize;

    public XMSSMTKeyParams(int height, int layers, AlgorithmIdentifier treeDigest, int treeDigestSize) {
        this.version = new ASN1Integer(0);
        this.height = height;
        this.layers = layers;
        this.treeDigest = treeDigest;
        this.treeDigestSize = treeDigestSize;
    }

    private XMSSMTKeyParams(ASN1Sequence sequence) {
        this.version = ASN1Integer.getInstance(sequence.getObjectAt(0));
        this.height = ASN1Integer.getInstance(sequence.getObjectAt(1)).intValueExact();
        this.layers = ASN1Integer.getInstance(sequence.getObjectAt(2)).intValueExact();
        this.treeDigest = AlgorithmIdentifier.getInstance(sequence.getObjectAt(3));
        this.treeDigestSize = ASN1Integer.getInstance(sequence.getObjectAt(4)).intValueExact();
    }

    public static XMSSMTKeyParams getInstance(Object o) {
        if (o instanceof XMSSMTKeyParams) {
            return (XMSSMTKeyParams) o;
        }
        if (o instanceof ASN1Null) {
            return null;
        } else if (o != null) {
            return new XMSSMTKeyParams(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public int getHeight() {
        return height;
    }

    public int getLayers() {
        return layers;
    }

    public AlgorithmIdentifier getTreeDigest() {
        return treeDigest;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(version);
        v.add(new ASN1Integer(height));
        v.add(new ASN1Integer(layers));
        v.add(treeDigest);
        v.add(new ASN1Integer(treeDigestSize));

        return new DERSequence(v);
    }
}
