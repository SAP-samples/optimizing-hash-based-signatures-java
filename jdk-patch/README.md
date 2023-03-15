# OpenJDK patch for bcpqc

Base commit: https://github.com/openjdk/jdk/commit/0f2113cee79b9645105b4753c7d7eacb83b872c2 (Tag ``jdk-18+36``)

This repo contains a patch for OpenJDK required for ``bcpqc``. This patch contains the following major changes:

- Publicly exposes ``sun.security.provider.SHA2`` to allow for direct access to the SHA2 compression function
- Provide intrinsics for Haraka by re-implementing the following existing methods with intrinsics:
	- Haraka256 hash: ``com.sun.crypto.provider.AESCrypt::encryptBlock``
	- Haraka512 hash: ``com.sun.crypto.provider.ElectronicCodeBook::encrypt``
	- Haraka512 permutation (for HarakaS): ``com.sun.crypto.provider.AESCrypt::decryptBlock``

**ATTENTION**: By repurposing existing intrinsics, this patch breaks existing JDK functionality. It is intended for evaluation purposes only and **MUST NOT** be used in any prodictive environment.

When executing Maven using a patched JDK, fetching dependencies will fail. Run Maven with another JDK (by setting ``JAVA_HOME``) to fetch dependencies. Afterwards, Maven can be re-run with this JDK to compile the project. 

## Generate Patch

git diff 0f2113cee79b9645105b4753c7d7eacb83b872c2 patch-public-sha > ../jdk-patch/jdk.patch

## Apply Patch and Build JDK
	
	# Install dependencies
	sudo apt install autoconf libfreetype6-dev libcups2-dev libx11-dev libxext-dev libxrender-dev libxrandr-dev libxtst-dev libxt-dev libasound2-dev zip libfontconfig1-dev

	# Clone and patch
	git clone https://github.com/openjdk/jdk.git
	cd jdk
	git checkout -b patched-jdk 0f2113cee79b9645105b4753c7d7eacb83b872c2
	git apply ../jdk-patch/jdk.patch

	# Compile
	bash configure
	make images


Resulting JDK in ``build/linux-x86_64-server-release/images/jdk/``.
