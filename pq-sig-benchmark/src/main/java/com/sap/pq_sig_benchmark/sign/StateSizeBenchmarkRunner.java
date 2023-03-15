package com.sap.pq_sig_benchmark.sign;


import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.pqc.jcajce.interfaces.XMSSPrivateKey;

import com.sap.pq_sig_benchmark.Parameters;
import org.example.bcpqc.pqc.jcajce.provider.xmss.BCXMSSMTPrivateKey;

public class StateSizeBenchmarkRunner {
	private static final long MAX_ITERATIONS = 100000;

	public static void main(String[] args) throws Exception {
		long iteration = 0;
		List<Integer> stateSizes = new ArrayList<>();
		
		String parameter = Parameters.SHA2_20_192;
		SignatureBenchmark benchmark = new XMSSSignatureBenchmark(parameter);
		benchmark.setUp();
		XMSSPrivateKey privKey = (XMSSPrivateKey) benchmark.kp.getPrivate();
		
		System.out.println("Starting iterations. Remaining signatures: " + privKey.getUsagesRemaining());
		while(privKey.getUsagesRemaining() >= 1 && iteration <= MAX_ITERATIONS) {
			stateSizes.add(privKey.getEncoded().length);
			benchmark.sign();
			iteration++;
			if(iteration % 1000 == 0) {
				System.out.println("# " + iteration);
			}
		}
		System.out.println("" + iteration + " iterations done");

		File outFile = new File("results/" + parameter);
		outFile.createNewFile();
		try(BufferedWriter writer = new BufferedWriter(new FileWriter(outFile))){
			for(Integer i : stateSizes) {
				// Appending ",0" is a hack to make excel recognize the value as numbers, not strings
				writer.write(i.toString() + ",0");
				writer.newLine();
			}
		}
		System.out.println("Results written to " + outFile.getAbsolutePath());
	}

}
