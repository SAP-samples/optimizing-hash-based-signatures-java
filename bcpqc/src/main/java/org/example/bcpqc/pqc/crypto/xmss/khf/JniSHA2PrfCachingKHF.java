package org.example.bcpqc.pqc.crypto.xmss.khf;

import org.example.bcpqc.pqc.crypto.xmss.PRFCacheHashMap;
import org.example.jnihash.JniHash;

public class JniSHA2PrfCachingKHF extends JniSHA2FixedPaddingKHF {

    private PRFCacheHashMap<JniHash.IntermediateState> prfCache = new PRFCacheHashMap<>(JniHash.IntermediateState.class);

    public JniSHA2PrfCachingKHF(int digestSize) {
        super(digestSize);
    }

    @Override
    public byte[] PRF_internal(byte[] key, byte[] address) {
        if (digestSize == 32) {
            byte[] out = new byte[32];
            JniHash.IntermediateState state = this.prfCache.get(key);
            if (state == null) {
                state = jniHash.sha2_256_xmss_prf_first_block(key);
                prfCache.add(key, state);
            }
            jniHash.sha2_256_768_lastBlock(state, address, out);
            return out;
        } else {
            byte[] out = new byte[24];
            jniHash.sha2_xmss_fixed_padding(3, this.paddingSize, JniSHA2FixedPaddingKHF._480, key, address, out);
            return out;
        }
    }

}
