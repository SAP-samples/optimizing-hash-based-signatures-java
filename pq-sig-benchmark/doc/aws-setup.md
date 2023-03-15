# AWS Machine Setup

Ubuntu 20.04 LTS 64-bit

    sudo apt update
    sudo apt full-upgrade
    sudo apt install build-essential unzip libssl-dev xsltproc
    sudo reboot                                                     # Kernel updates

Copy benchmark-artifacts.zip

## JDK, Maven

    sudo apt install autoconf libfreetype6-dev libcups2-dev libx11-dev libxext-dev libxrender-dev libxrandr-dev libxtst-dev libxt-dev libasound2-dev zip libfontconfig1-dev

    # Boot JDK
    wget https://download.java.net/java/GA/jdk18.0.2.1/db379da656dc47308e138f21b33976fa/1/GPL/openjdk-18.0.2.1_linux-x64_bin.tar.gz
    tar -zxf openjdk-18.0.2.1_linux-x64_bin.tar.gz

    unzip jdk-patch-public-sha.zip
    cd jdk-patch-public-sha
    bash configure --with-boot-jdk=../jdk-18.0.2.1
    make images

    wget https://dlcdn.apache.org/maven/maven-3/3.8.7/binaries/apache-maven-3.8.7-bin.tar.gz
    tar -zxf apache-maven-3.8.7-bin.tar.gz


``.bash_profile``:

    JAVA_HOME='/home/ubuntu/jdk-patch-public-sha/build/linux-x86_64-server-release/images/jdk'
    M2_HOME='/home/ubuntu/apache-maven-3.8.7'
    PATH="$JAVA_HOME/bin:$M2_HOME/bin:$PATH"
    export PATH
    

Aktivieren mit:
    
    source .bash_profile

## Screen setup

	# .screenrc:

	caption always "%{rw} * | %H * $LOGNAME | %{bw}%c %D | %{-}%-Lw%{rw}%50>%{rW}%n%f* %t %{-}%+Lw%<"
	
	# .bash_profile
	if [ "$TERM" != "screen" ] && [ "$SSH_CONNECTION" != "" ]; then
	   /usr/bin/screen -S sshscreen -d -R && exit
	fi

Taken from https://wiki.ubuntuusers.de/Screen

## XKCP

    git clone https://github.com/XKCP/XKCP.git
    cd XKCP

Edit ``Makefile.build``:

    <fragment name="libXKCP.a" inherits="All">
        <gcc>-fPIC</gcc>
    </fragment>

Build:

    make AVX512/libXKCP.a 
    # Move AVX512 version to AVX2 directory to avoid changing paths in depending projects
    cp -r bin/AVX512/ bin/AVX2/

## jni-hash

    cd jni-hash-master
    JAVA_HOME=../jdk-18.0.2.1 mvn native:compile
    JAVA_HOME=../jdk-18.0.2.1 mvn native:link
    JAVA_HOME=../jdk-18.0.2.1 mvn install
    
    sudo mkdir -p /usr/java/packages/lib
    sudo cp target/libnative.so /usr/java/packages/lib

## bcpqc

    # Download dependencies - some commands might fail
    JAVA_HOME=../jdk-18.0.2.1 mvn install 
    mvn install
    JAVA_HOME=../jdk-18.0.2.1 mvn install

## pq-sig-benchmark
    
    JAVA_HOME=../jdk-18.0.2.1 mvn verify


    sudo systemctl disable snapd
    sudo systemctl stop snapd