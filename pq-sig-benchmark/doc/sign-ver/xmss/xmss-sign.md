Sign and Verify:

java --add-exports=java.base/sun.security.provider=ALL-UNNAMED --add-opens=java.base/sun.security.provider=ALL-UNNAMED --add-exports=java.base/com.sun.crypto.provider=ALL-UNNAMED --add-opens=java.base/com.sun.crypto.provider=ALL-UNNAMED -jar target/benchmarks.jar -f 1 -i 50 -wi 20 -w 1s -r 1s -to 90min -rf csv -p hashingProvider=bc,bc-optimized,corretto,jni,jni-fixed-padding,jni-prf-cache,java,java-optimized -p xmss_parameter=SHA2_10_256,SHA2_16_256,SHA2_10_192,SHA2_16_192,SHAKE256_10_256,SHAKE256_16_256,SHAKE256_10_192,SHAKE256_16_192 "XMSSSignatureBenchmark|XMSSVerificationBenchmark"  | tee xmss-sign-ver.log; sudo systemctl poweroff


Test:
java --add-exports=java.base/sun.security.provider=ALL-UNNAMED --add-opens=java.base/sun.security.provider=ALL-UNNAMED --add-exports=java.base/com.sun.crypto.provider=ALL-UNNAMED --add-opens=java.base/com.sun.crypto.provider=ALL-UNNAMED -jar target/benchmarks.jar -f 1 -i 5 -wi 0 -r 1s -to 90min -p hashingProvider=bc,bc-optimized,corretto,jni,jni-fixed-padding,jni-prf-cache,java,java-optimized -p xmss_parameter=SHA2_10_256,SHA2_16_256,SHA2_10_192,SHA2_16_192,SHAKE256_10_256,SHAKE256_16_256,SHAKE256_10_192,SHAKE256_16_192 "XMSSSignatureBenchmark|XMSSVerificationBenchmark"
SHA2_10_192:
java --add-exports=java.base/sun.security.provider=ALL-UNNAMED --add-opens=java.base/sun.security.provider=ALL-UNNAMED --add-exports=java.base/com.sun.crypto.provider=ALL-UNNAMED --add-opens=java.base/com.sun.crypto.provider=ALL-UNNAMED -jar target/benchmarks.jar -f 1 -i 5 -wi 0 -r 1s -to 90min -p hashingProvider=bc,bc-optimized,corretto,jni,jni-fixed-padding,jni-prf-cache,java,java-optimized -p xmss_parameter=SHA2_10_192 "XMSSSignatureBenchmark"


-p hashingProvider=bc,bc-optimized,corretto,jni,jni-fixed-padding,jni-prf-cache,java,java-optimized