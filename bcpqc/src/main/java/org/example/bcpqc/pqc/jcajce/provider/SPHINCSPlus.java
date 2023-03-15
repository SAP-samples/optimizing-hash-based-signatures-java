package org.example.bcpqc.pqc.jcajce.provider;


import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.example.bcpqc.asn1.bc.SAPBCObjectIdentifiers;
import org.example.bcpqc.pqc.jcajce.provider.sphincsplus.SPHINCSPlusKeyFactorySpi;

public class SPHINCSPlus {
    private static final String PREFIX = "org.example.bcpqc.pqc.jcajce.provider" + ".sphincsplus.";

    public static class Mappings
            extends AsymmetricAlgorithmProvider {
        public Mappings() {
        }

        public void configure(ConfigurableProvider provider) {
            provider.addAlgorithm("KeyFactory.SPHINCSPLUS", PREFIX + "SPHINCSPlusKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.SPHINCSPLUS", PREFIX + "SPHINCSPlusKeyPairGeneratorSpi");
            provider.addAlgorithm("Alg.Alias.KeyFactory.SPHINCS+", "SPHINCSPLUS");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.SPHINCS+", "SPHINCSPLUS");

            addSignatureAlgorithm(provider, "SPHINCSPLUS", PREFIX + "SignatureSpi$Direct", SAPBCObjectIdentifiers.sphincsPlus);

            addSignatureAlias(provider, "SPHINCSPLUS", SAPBCObjectIdentifiers.sphincsPlus_shake_256);
            addSignatureAlias(provider, "SPHINCSPLUS", SAPBCObjectIdentifiers.sphincsPlus_sha_256);
            addSignatureAlias(provider, "SPHINCSPLUS", SAPBCObjectIdentifiers.sphincsPlus_sha_512);
            addSignatureAlias(provider, "SPHINCSPLUS", SAPBCObjectIdentifiers.sphincsPlus_haraka);

            provider.addAlgorithm("Alg.Alias.Signature.SPHINCS+", "SPHINCSPLUS");

            AsymmetricKeyInfoConverter keyFact = new SPHINCSPlusKeyFactorySpi();

            registerOid(provider, SAPBCObjectIdentifiers.sphincsPlus, "SPHINCSPLUS", keyFact);
            registerOid(provider, SAPBCObjectIdentifiers.sphincsPlus_shake_256, "SPHINCSPLUS", keyFact);
            registerOid(provider, SAPBCObjectIdentifiers.sphincsPlus_sha_256, "SPHINCSPLUS", keyFact);
            registerOid(provider, SAPBCObjectIdentifiers.sphincsPlus_sha_512, "SPHINCSPLUS", keyFact);
            registerOid(provider, SAPBCObjectIdentifiers.sphincsPlus_haraka, "SPHINCSPLUS", keyFact);
        }

        private void addSignatureAlias(
                ConfigurableProvider provider,
                String algorithm,
                ASN1ObjectIdentifier oid) {
            provider.addAlgorithm("Alg.Alias.Signature." + oid, algorithm);
            provider.addAlgorithm("Alg.Alias.Signature.OID." + oid, algorithm);
        }
    }
}
