package org.example.bcpqc.pqc.crypto.intrinsics;

import com.sun.crypto.provider.AESCrypt;
import com.sun.crypto.provider.ElectronicCodeBook;
import junit.framework.TestCase;
import org.bouncycastle.util.encoders.Hex;
import org.example.bcpqc.crypto.digests.haraka.JavaIntrinsicHaraka256;
import org.example.bcpqc.crypto.digests.haraka.JavaIntrinsicHaraka512;
import org.example.bcpqc.crypto.digests.haraka.JavaIntrinsicHarakaS;

import java.math.BigInteger;

public class JavaIntrinsicHarakaTest extends TestCase {

    public static final String[] rcStrings = {
            "0684704ce620c00ab2c5fef075817b9d", "8b66b4e188f3a06b640f6ba42f08f717",
            "3402de2d53f28498cf029d609f029114", "0ed6eae62e7b4f08bbf3bcaffd5b4f79",
            "cbcfb0cb4872448b79eecd1cbe397044", "7eeacdee6e9032b78d5335ed2b8a057b",
            "67c28f435e2e7cd0e2412761da4fef1b", "2924d9b0afcacc07675ffde21fc70b3b",
            "ab4d63f1e6867fe9ecdb8fcab9d465ee", "1c30bf84d4b7cd645b2a404fad037e33",
            "b2cc0bb9941723bf69028b2e8df69800", "fa0478a6de6f55724aaa9ec85c9d2d8a",
            "dfb49f2b6b772a120efa4f2e29129fd4", "1ea10344f449a23632d611aebb6a12ee",
            "af0449884b0500845f9600c99ca8eca6", "21025ed89d199c4f78a2c7e327e593ec",
            "bf3aaaf8a759c9b7b9282ecd82d40173", "6260700d6186b01737f2efd910307d6b",
            "5aca45c22130044381c29153f6fc9ac6", "9223973c226b68bb2caf92e836d1943a",
            "d3bf9238225886eb6cbab958e51071b4", "db863ce5aef0c677933dfddd24e1128d",
            "bb606268ffeba09c83e48de3cb2212b1", "734bd3dce2e4d19c2db91a4ec72bf77d",
            "43bb47c361301b434b1415c42cb3924e", "dba775a8e707eff603b231dd16eb6899",
            "6df3614b3c7559778e5e23027eca472c", "cda75a17d6de7d776d1be5b9b88617f9",
            "ec6b43f06ba8e9aa9d6c069da946ee5d", "cb1e6950f957332ba25311593bf327c1",
            "2cee0c7500da619ce4ed0353600ed0d9", "f0b1a5a196e90cab80bbbabc63a4a350",
            "ae3db1025e962988ab0dde30938dca39", "17bb8f38d554a40b8814f3a82e75b442",
            "34bb8a5b5f427fd7aeb6b779360a16f6", "26f65241cbe5543843ce5918ffbaafde",
            "4ce99a54b9f3026aa2ca9cf7839ec978", "ae51a51a1bdff7be40c06e2822901235",
            "a0c1613cba7ed22bc173bc0f48a659cf", "756acc03022882884ad6bdfde9c59da1"
    };

    public static void main(String[] args) {
        // Convert round constants
        byte[] rcBytes = new byte[40 * 16];
        for (int i = 0; i < 40; i++) {
            BigInteger bi = new BigInteger(rcStrings[i], 16);
            byte[] ba = bi.toByteArray();
            int offset = ba.length - 16; // Sometimes ba contains a leading 0
            for (int j = 0; j < 16; j++) {

                rcBytes[(i * 16) + j] = ba[15 - j + offset];
            }
        }

        System.out.println(Hex.toHexString(rcBytes));
        for (byte b : rcBytes) {
            System.out.print(b);
            System.out.print(", ");
        }
        System.out.println();


        AESCrypt aesCrypt = new AESCrypt();

        {
            System.out.println("Haraka256");

            byte[] in = new byte[32];
            for (int i = 0; i < in.length; i++)
                in[i] = (byte) (i);
            System.out.println(Hex.toHexString(in));

            byte[] inCopy = new byte[in.length];
            byte[] out = new byte[32];

            for (int i = 0; i < 100000000; i++) {
                System.arraycopy(in, 0, inCopy, 0, in.length);
                aesCrypt.encryptBlock(inCopy, 0, rcBytes, 0);
            }

            System.out.println(Hex.toHexString(inCopy));
            System.out.println(Hex.toHexString(rcBytes));
        }


        {
            System.out.println("Haraka512");
            byte[] in = new byte[64];
            for (int i = 0; i < in.length; i++)
                in[i] = (byte) (i);
            System.out.println(Hex.toHexString(in));

            byte[] inCopy = new byte[in.length];
            byte[] out = new byte[64];

            for (int i = 0; i < 100000000; i++) {
                System.arraycopy(in, 0, inCopy, 0, in.length);
                aesCrypt.decryptBlock(inCopy, 0, rcBytes, 0);
            }

            System.out.println(Hex.toHexString(inCopy));
            System.out.println(Hex.toHexString(rcBytes));
        }


        ElectronicCodeBook electronicCodeBook = new ElectronicCodeBook(aesCrypt);

        {
            System.out.println("ECB Test");

            byte[] in = new byte[64];
            for (int i = 0; i < in.length; i++)
                in[i] = (byte) (i);
            System.out.println(Hex.toHexString(in));
            byte[] inCopy = new byte[in.length];

            for (int i = 0; i < 100000000; i++) {
                System.arraycopy(in, 0, inCopy, 0, in.length);
                electronicCodeBook.encrypt(inCopy, 0, in.length, rcBytes, 0);
            }

            System.out.println(Hex.toHexString(inCopy));
            System.out.println(Hex.toHexString(rcBytes));

        }
    }

    /**
     * Iterate to ensure intrinsic is used
     */
    public void testHarakaIntrinsic256_512DefaultRC() {
        JavaIntrinsicHaraka256 javaIntrinsicHaraka256 = new JavaIntrinsicHaraka256(new JavaIntrinsicHarakaS());

        byte[] in = new byte[64];
        for (int i = 0; i < in.length; i++)
            in[i] = (byte) (i);
        System.out.println(Hex.toHexString(in));
        byte[] out = null;

        for (int i = 0; i < 100000000; i++) {
            javaIntrinsicHaraka256.update(in, 0, 32);
            out = javaIntrinsicHaraka256.digest(32);
            javaIntrinsicHaraka256.reset();
        }

        assertEquals("8027ccb87949774b78d0545fb72bf70c695c2a0923cbd47bba1159efbf2b2c1c", Hex.toHexString(out));
        System.out.println(Hex.toHexString(out));


        JavaIntrinsicHaraka512 javaIntrinsicHaraka512 = new JavaIntrinsicHaraka512(new JavaIntrinsicHarakaS());

        for (int i = 0; i < 100000000; i++) {
            javaIntrinsicHaraka512.update(in, 0, 64);
            out = javaIntrinsicHaraka512.digest(32);
            javaIntrinsicHaraka512.reset();
        }

        assertEquals("be7f723b4e80a99813b292287f306f625a6d57331cae5f34dd9277b0945be2aa", Hex.toHexString(out));
        System.out.println(Hex.toHexString(out));
    }

    /**
     * Don't iterate to test Java code
     */
    public void testHarakaJava256_512DefaultRC() {
        JavaIntrinsicHaraka256 javaIntrinsicHaraka256 = new JavaIntrinsicHaraka256(new JavaIntrinsicHarakaS());

        byte[] in = new byte[64];
        for (int i = 0; i < in.length; i++)
            in[i] = (byte) (i);
        System.out.println(Hex.toHexString(in));
        byte[] out = null;

        javaIntrinsicHaraka256.update(in, 0, 32);
        out = javaIntrinsicHaraka256.digest(32);
        javaIntrinsicHaraka256.reset();

        assertEquals("8027ccb87949774b78d0545fb72bf70c695c2a0923cbd47bba1159efbf2b2c1c", Hex.toHexString(out));
        System.out.println(Hex.toHexString(out));


        JavaIntrinsicHaraka512 javaIntrinsicHaraka512 = new JavaIntrinsicHaraka512(new JavaIntrinsicHarakaS());

        javaIntrinsicHaraka512.update(in, 0, 64);
        out = javaIntrinsicHaraka512.digest(32);
        javaIntrinsicHaraka512.reset();

        assertEquals("be7f723b4e80a99813b292287f306f625a6d57331cae5f34dd9277b0945be2aa", Hex.toHexString(out));
        System.out.println(Hex.toHexString(out));
    }
}
