m5zn/m6i.xlarge ohne HT

JAVA_HOME=../jdk-18.0.2.1 mvn native:compile
JAVA_HOME=../jdk-18.0.2.1 mvn native:link
JAVA_HOME=../jdk-18.0.2.1 mvn verify


java -jar target/benchmarks.jar -rf csv | tee jni-transfer-log.txt; sudo systemctl poweroff