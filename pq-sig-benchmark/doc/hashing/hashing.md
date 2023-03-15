# XMSS Hashing

## F
java --add-exports=java.base/sun.security.provider=ALL-UNNAMED --add-opens=java.base/sun.security.provider=ALL-UNNAMED --add-exports=java.base/com.sun.crypto.provider=ALL-UNNAMED --add-opens=java.base/com.sun.crypto.provider=ALL-UNNAMED -jar target/benchmarks.jar -f 1 -i 50 -wi 2 -r 1s -rf csv -p digestName=SHA-256,SHAKE256 XMSSHashBenchmark | tee hash-f.log; sudo systemctl poweroff

## PRF

nano src/main/java/com/sap/pq_sig_benchmark/hash/XMSSHashBenchmark.java
mvn clean verify

java --add-exports=java.base/sun.security.provider=ALL-UNNAMED --add-opens=java.base/sun.security.provider=ALL-UNNAMED --add-exports=java.base/com.sun.crypto.provider=ALL-UNNAMED --add-opens=java.base/com.sun.crypto.provider=ALL-UNNAMED -jar target/benchmarks.jar -f 1 -i 50 -wi 2 -r 1s -rf csv -p paramSize=32 -p digestName=SHA-256 XMSSHashBenchmark | tee hash-prf.log; sudo systemctl poweroff



# SPHINCS+ Hashing

java --add-exports=java.base/sun.security.provider=ALL-UNNAMED --add-opens=java.base/sun.security.provider=ALL-UNNAMED --add-exports=java.base/com.sun.crypto.provider=ALL-UNNAMED --add-opens=java.base/com.sun.crypto.provider=ALL-UNNAMED -jar target/benchmarks.jar -f 1 -i 50 -wi 2 -r 1s -rf csv -p digestName=SHA-256,SHAKE256,Haraka -p hashingProvider=bc,jni,java SPHINCSPlusHashBenchmark | tee sphincs-hash.log; sudo systemctl poweroff

Test:
java --add-exports=java.base/sun.security.provider=ALL-UNNAMED --add-opens=java.base/sun.security.provider=ALL-UNNAMED --add-exports=java.base/com.sun.crypto.provider=ALL-UNNAMED --add-opens=java.base/com.sun.crypto.provider=ALL-UNNAMED -jar target/benchmarks.jar -f 1 -i 1 -wi 0 -r 1s -p digestName=SHA-256,SHAKE256,Haraka -p hashingProvider=bc,jni,java SPHINCSPlusHashBenchmark