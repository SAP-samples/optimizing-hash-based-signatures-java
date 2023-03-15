m6i.xlarge, ohne HT

java --add-exports=java.base/sun.security.provider=ALL-UNNAMED --add-opens=java.base/sun.security.provider=ALL-UNNAMED --add-exports=java.base/com.sun.crypto.provider=ALL-UNNAMED --add-opens=java.base/com.sun.crypto.provider=ALL-UNNAMED -jar target/benchmarks.jar -rf csv -f 1 WOTSPlusCBenchmark | tee wotsc-log.txt; sudo systemctl poweroff