java --add-exports=java.base/sun.security.provider=ALL-UNNAMED --add-opens=java.base/sun.security.provider=ALL-UNNAMED --add-exports=java.base/com.sun.crypto.provider=ALL-UNNAMED --add-opens=java.base/com.sun.crypto.provider=ALL-UNNAMED -jar target/benchmarks.jar -f 1 -i 10 -wi 2 -r 20s -to 10min -rf csv -p lms_sig_parameter=lms_sha256_m32_h5,lms_sha256_m32_h10,lms_sha256_m32_h15,lms_sha256_m24_h5,lms_sha256_m24_h10,lms_sha256_m24_h15,lms_shake_m32_h5,lms_shake_m32_h10,lms_shake_m32_h15,lms_shake_m24_h5,lms_shake_m24_h10,lms_shake_m24_h15 -tu ms LMSKeyGenerationBenchmark | tee lms-keygen.log; sudo systemctl poweroff


Test:
java --add-exports=java.base/sun.security.provider=ALL-UNNAMED --add-opens=java.base/sun.security.provider=ALL-UNNAMED --add-exports=java.base/com.sun.crypto.provider=ALL-UNNAMED --add-opens=java.base/com.sun.crypto.provider=ALL-UNNAMED -jar target/benchmarks.jar -f 1 -i 1 -wi 0 -r 1s -to 10min -p lms_sig_parameter=lms_sha256_m32_h5,lms_shake_m24_h5 -tu ms LMSKeyGenerationBenchmark