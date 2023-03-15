# Reference

m5zn.xlarge, m6i.xlarge ohne HT

    make

## Hashing
    
    cd ../jni-hash-master
    bash make_benchmark.sh
    ./target/benchmark | tee hash-benchmark.txt; sudo systemctl poweroff

## XMSS Hashing

    ./test/hash_speed | tee hash-speed.txt

## XMSS

    ./test/speed | tee speed.txt; sudo systemctl poweroff