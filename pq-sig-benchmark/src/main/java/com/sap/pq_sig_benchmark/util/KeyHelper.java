package com.sap.pq_sig_benchmark.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.function.Function;

public class KeyHelper {
	public static KeyPair loadKeyPair(String path, KeyFactory keyFactory) throws InvalidKeySpecException, IOException {
		File privKeyFile = new File(path);
		File pubKeyFile = new File(path + ".pub");

		if (privKeyFile.exists()) {
			PrivateKey privKey;
			PublicKey pubKey;
			try (FileInputStream privInputStream = new FileInputStream(privKeyFile)) {
				privKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privInputStream.readAllBytes()));
			}
			try (FileInputStream pubInputStream = new FileInputStream(pubKeyFile)) {
				pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(pubInputStream.readAllBytes()));
			}
			return new KeyPair(pubKey, privKey);
		}

		return null;
	}

	public static void writeKeyPair(String path, KeyPair keyPair) throws IOException {
		if(keyPair.getPrivate().getEncoded() == null || keyPair.getPublic().getEncoded() == null){
			// E.g. SPHINCS+ apparently does not support serialization
			return;
		}
		File privKeyFile = new File(path);
		File pubKeyFile = new File(path + ".pub");

		try (FileOutputStream privOutputStream = new FileOutputStream(privKeyFile)) {
			privOutputStream.write(keyPair.getPrivate().getEncoded());
		}
		try (FileOutputStream pubOutputStream = new FileOutputStream(pubKeyFile)) {
			pubOutputStream.write(keyPair.getPublic().getEncoded());
		}
		System.out.println("Generated key written to " + path);
	}

	public static KeyPair loadOrGenerateKeyPair(String keyPath, KeyFactory keyFactory, KeyPairGenerator keyPairGenerator,
												AlgorithmParameterSpec algorithmParameterSpec, Function<KeyPair, KeyPair> newKeyLambda)
			throws InvalidAlgorithmParameterException, IOException, InvalidKeySpecException {
		KeyPair keyPair = KeyHelper.loadKeyPair(keyPath, keyFactory);
		if (keyPair == null) {
			keyPairGenerator.initialize(algorithmParameterSpec, new SecureRandom());
			keyPair = keyPairGenerator.generateKeyPair();
			if(newKeyLambda != null){
				keyPair = newKeyLambda.apply(keyPair);
			}
			KeyHelper.writeKeyPair(keyPath, keyPair);
		}
		return keyPair;
	}
}
