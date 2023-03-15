package org.example.bcpqc.pqc.crypto.util;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.XMSSMTPrivateKey;
import org.bouncycastle.pqc.asn1.XMSSPrivateKey;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;
import org.example.bcpqc.asn1.bc.SAPBCObjectIdentifiers;
import org.example.bcpqc.pqc.asn1.XMSSKeyParams;
import org.example.bcpqc.pqc.asn1.XMSSMTKeyParams;
import org.example.bcpqc.pqc.crypto.lms.HSSPrivateKeyParameters;
import org.example.bcpqc.pqc.crypto.lms.LMSPrivateKeyParameters;
import org.example.bcpqc.pqc.crypto.sphincsplus.SPHINCSPlusParameters;
import org.example.bcpqc.pqc.crypto.sphincsplus.SPHINCSPlusPrivateKeyParameters;
import org.example.bcpqc.pqc.crypto.xmss.*;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

/**
 * Factory for creating private key objects from PKCS8 PrivateKeyInfo objects.
 */
public class PrivateKeyFactory {
    /**
     * Create a private key parameter from a PKCS8 PrivateKeyInfo encoding.
     *
     * @param privateKeyInfoData the PrivateKeyInfo encoding
     * @return a suitable private key parameter
     * @throws IOException on an error decoding the key
     */
    public static AsymmetricKeyParameter createKey(byte[] privateKeyInfoData) throws IOException {
        return createKey(PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(privateKeyInfoData)));
    }

    /**
     * Create a private key parameter from a PKCS8 PrivateKeyInfo encoding read from a
     * stream.
     *
     * @param inStr the stream to read the PrivateKeyInfo encoding from
     * @return a suitable private key parameter
     * @throws IOException on an error decoding the key
     */
    public static AsymmetricKeyParameter createKey(InputStream inStr) throws IOException {
        return createKey(PrivateKeyInfo.getInstance(new ASN1InputStream(inStr).readObject()));
    }

    /**
     * Create a private key parameter from the passed in PKCS8 PrivateKeyInfo object.
     *
     * @param keyInfo the PrivateKeyInfo object containing the key material
     * @return a suitable private key parameter
     * @throws IOException on an error decoding the key
     */
    public static AsymmetricKeyParameter createKey(PrivateKeyInfo keyInfo) throws IOException {
        AlgorithmIdentifier algId = keyInfo.getPrivateKeyAlgorithm();
        ASN1ObjectIdentifier algOID = algId.getAlgorithm();

        /*
        if (algOID.on(BCObjectIdentifiers.qTESLA))
        {
            ASN1OctetString qTESLAPriv = ASN1OctetString.getInstance(keyInfo.parsePrivateKey());

            return new QTESLAPrivateKeyParameters(org.bouncycastle.pqc.crypto.util.Utils.qTeslaLookupSecurityCategory(keyInfo.getPrivateKeyAlgorithm()), qTESLAPriv.getOctets());
        }
        else if (algOID.equals(BCObjectIdentifiers.sphincs256))
        {
            return new SPHINCSPrivateKeyParameters(ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets(),
                org.bouncycastle.pqc.crypto.util.Utils.sphincs256LookupTreeAlgName(SPHINCS256KeyParams.getInstance(keyInfo.getPrivateKeyAlgorithm().getParameters())));
        }
        else if (algOID.equals(BCObjectIdentifiers.newHope))
        {
            return new NHPrivateKeyParameters(convert(ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets()));
        }
        else */
        if (algOID.equals(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig)) {
            byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
            ASN1BitString pubKey = keyInfo.getPublicKeyData();

            if (Pack.bigEndianToInt(keyEnc, 0) == 1) {
                if (pubKey != null) {
                    byte[] pubEnc = pubKey.getOctets();

                    return LMSPrivateKeyParameters.getInstance(Arrays.copyOfRange(keyEnc, 4, keyEnc.length), Arrays.copyOfRange(pubEnc, 4, pubEnc.length));
                }
                return LMSPrivateKeyParameters.getInstance(Arrays.copyOfRange(keyEnc, 4, keyEnc.length));
            } else {
                if (pubKey != null) {
                    byte[] pubEnc = pubKey.getOctets();

                    return HSSPrivateKeyParameters.getInstance(Arrays.copyOfRange(keyEnc, 4, keyEnc.length), pubEnc);
                }
                return HSSPrivateKeyParameters.getInstance(Arrays.copyOfRange(keyEnc, 4, keyEnc.length));
            }
        } else if (algOID.on(SAPBCObjectIdentifiers.sphincsPlus)) {
            byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
            SPHINCSPlusParameters spParams = SPHINCSPlusParameters.getParams(Integers.valueOf(Pack.bigEndianToInt(keyEnc, 0)));

            return new SPHINCSPlusPrivateKeyParameters(spParams, Arrays.copyOfRange(keyEnc, 4, keyEnc.length));
        }
        /*
        else if (algOID.on(BCObjectIdentifiers.pqc_kem_mceliece))
        {
            CMCEPrivateKey cmceKey = CMCEPrivateKey.getInstance(keyInfo.parsePrivateKey());
            CMCEParameters spParams = org.bouncycastle.pqc.crypto.util.Utils.mcElieceParamsLookup(keyInfo.getPrivateKeyAlgorithm().getAlgorithm());

            return new CMCEPrivateKeyParameters(spParams, cmceKey.getDelta(), cmceKey.getC(), cmceKey.getG(), cmceKey.getAlpha(), cmceKey.getS());
        }
        else if (algOID.on(BCObjectIdentifiers.pqc_kem_frodo))
        {
            byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
            FrodoParameters spParams = org.bouncycastle.pqc.crypto.util.Utils.frodoParamsLookup(keyInfo.getPrivateKeyAlgorithm().getAlgorithm());

            return new FrodoPrivateKeyParameters(spParams, keyEnc);
        }
        else if (algOID.on(BCObjectIdentifiers.pqc_kem_saber))
        {
            byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
            SABERParameters spParams = org.bouncycastle.pqc.crypto.util.Utils.saberParamsLookup(keyInfo.getPrivateKeyAlgorithm().getAlgorithm());

            return new SABERPrivateKeyParameters(spParams, keyEnc);
        } */
        else if (algOID.equals(BCObjectIdentifiers.xmss)) {
            XMSSKeyParams keyParams = XMSSKeyParams.getInstance(keyInfo.getPrivateKeyAlgorithm().getParameters());
            ASN1ObjectIdentifier treeDigest = keyParams.getTreeDigest().getAlgorithm();

            XMSSPrivateKey xmssPrivateKey = XMSSPrivateKey.getInstance(keyInfo.parsePrivateKey());

            try {
                XMSSPrivateKeyParameters.Builder keyBuilder = new XMSSPrivateKeyParameters
                        .Builder(new XMSSParameters(keyParams.getHeight(), treeDigest, keyParams.getDigestSize()))
                        .withIndex(xmssPrivateKey.getIndex())
                        .withSecretKeySeed(xmssPrivateKey.getSecretKeySeed())
                        .withSecretKeyPRF(xmssPrivateKey.getSecretKeyPRF())
                        .withPublicSeed(xmssPrivateKey.getPublicSeed())
                        .withRoot(xmssPrivateKey.getRoot());

                if (xmssPrivateKey.getVersion() != 0) {
                    keyBuilder.withMaxIndex(xmssPrivateKey.getMaxIndex());
                }

                if (xmssPrivateKey.getBdsState() != null) {
                    BDS bds = (BDS) XMSSUtil.deserialize(xmssPrivateKey.getBdsState(), BDS.class);
                    keyBuilder.withBDSState(bds.withWOTSDigest(new WOTSPlusParameters(treeDigest, keyParams.getDigestSize())));
                }

                return keyBuilder.build();
            } catch (ClassNotFoundException e) {
                throw new IOException("ClassNotFoundException processing BDS state: " + e.getMessage());
            }
        } else if (algOID.equals(PQCObjectIdentifiers.xmss_mt)) {
            XMSSMTKeyParams keyParams = XMSSMTKeyParams.getInstance(keyInfo.getPrivateKeyAlgorithm().getParameters());
            ASN1ObjectIdentifier treeDigest = keyParams.getTreeDigest().getAlgorithm();

            try {
                XMSSMTPrivateKey xmssMtPrivateKey = XMSSMTPrivateKey.getInstance(keyInfo.parsePrivateKey());

                XMSSMTPrivateKeyParameters.Builder keyBuilder = new XMSSMTPrivateKeyParameters
                        .Builder(new XMSSMTParameters(keyParams.getHeight(), keyParams.getLayers(), treeDigest, keyParams.getTreeDigestSize()))
                        .withIndex(xmssMtPrivateKey.getIndex())
                        .withSecretKeySeed(xmssMtPrivateKey.getSecretKeySeed())
                        .withSecretKeyPRF(xmssMtPrivateKey.getSecretKeyPRF())
                        .withPublicSeed(xmssMtPrivateKey.getPublicSeed())
                        .withRoot(xmssMtPrivateKey.getRoot());

                if (xmssMtPrivateKey.getVersion() != 0) {
                    keyBuilder.withMaxIndex(xmssMtPrivateKey.getMaxIndex());
                }

                if (xmssMtPrivateKey.getBdsState() != null) {
                    BDSStateMap bdsState = (BDSStateMap) XMSSUtil.deserialize(xmssMtPrivateKey.getBdsState(), BDSStateMap.class);
                    keyBuilder.withBDSState(bdsState.withWOTSDigest(new WOTSPlusParameters(treeDigest, keyParams.getTreeDigestSize())));
                }

                return keyBuilder.build();
            } catch (ClassNotFoundException e) {
                throw new IOException("ClassNotFoundException processing BDS state: " + e.getMessage());
            }
        }
        /*
        else if (algOID.equals(PQCObjectIdentifiers.mcElieceCca2)) {
            McElieceCCA2PrivateKey mKey = McElieceCCA2PrivateKey.getInstance(keyInfo.parsePrivateKey());

            return new McElieceCCA2PrivateKeyParameters(mKey.getN(), mKey.getK(), mKey.getField(), mKey.getGoppaPoly(), mKey.getP(), org.bouncycastle.pqc.crypto.util.Utils.getDigestName(mKey.getDigest().getAlgorithm()));
        }
        */
        else {
            throw new RuntimeException("algorithm identifier in private key not recognised");
        }
    }

    private static short[] convert(byte[] octets) {
        short[] rv = new short[octets.length / 2];

        for (int i = 0; i != rv.length; i++) {
            rv[i] = Pack.littleEndianToShort(octets, i * 2);
        }

        return rv;
    }
}