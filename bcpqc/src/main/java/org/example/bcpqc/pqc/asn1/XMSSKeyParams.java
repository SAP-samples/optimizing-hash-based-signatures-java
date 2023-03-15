package org.example.bcpqc.pqc.asn1;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * XMSSKeyParams
 * <pre>
 *     XMSSKeyParams ::= SEQUENCE {
 *     version INTEGER -- 0
 *     height INTEGER
 *     treeDigest AlgorithmIdentifier
 * }
 * </pre>
 */
public class XMSSKeyParams
        extends ASN1Object {
    private final ASN1Integer version;
    private final int height;
    private final AlgorithmIdentifier treeDigest;
    private final int digestSize;

    public XMSSKeyParams(int height, AlgorithmIdentifier treeDigest, int digestSize) {
        this.version = new ASN1Integer(0);
        this.height = height;
        this.treeDigest = treeDigest;
        this.digestSize = digestSize;
    }

    private XMSSKeyParams(ASN1Sequence sequence) {
        this.version = ASN1Integer.getInstance(sequence.getObjectAt(0));
        this.height = ASN1Integer.getInstance(sequence.getObjectAt(1)).intValueExact();
        this.treeDigest = AlgorithmIdentifier.getInstance(sequence.getObjectAt(2));
        this.digestSize = ASN1Integer.getInstance(sequence.getObjectAt(3)).intValueExact();
    }

    public static XMSSKeyParams getInstance(Object o) {
        if (o instanceof XMSSKeyParams) {
            return (XMSSKeyParams) o;
        }
        if (o instanceof ASN1Null) {
            return null;
        } else if (o != null) {
            return new XMSSKeyParams(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public int getHeight() {
        return height;
    }

    public AlgorithmIdentifier getTreeDigest() {
        return treeDigest;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(version);
        v.add(new ASN1Integer(height));
        v.add(treeDigest);
        v.add(new ASN1Integer(digestSize));

        return new DERSequence(v);
    }

    public int getDigestSize() {
        return digestSize;
    }
}
