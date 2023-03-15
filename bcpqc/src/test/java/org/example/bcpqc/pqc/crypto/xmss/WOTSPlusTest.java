package org.example.bcpqc.pqc.crypto.xmss;

import junit.framework.TestCase;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.util.encoders.Hex;

public class WOTSPlusTest extends TestCase {
    public void testWotsPlus() {
        WOTSPlusParameters params = new WOTSPlusParameters(NISTObjectIdentifiers.id_sha256, 32);
        WOTSPlus wotsPlus = new WOTSPlus(params);

        byte[] privSeed = new byte[32];
        privSeed[0] = 12;
        byte[] pubSeed = new byte[32];
        pubSeed[0] = 34;
        byte[] digest = new byte[32];
        digest[0] = 56;
        OTSHashAddress otsAddress = (OTSHashAddress) new OTSHashAddress.Builder().build();

        wotsPlus.importKeys(privSeed, pubSeed);


        WOTSPlusPublicKeyParameters publicKey = wotsPlus.getPublicKey(otsAddress);
        assertEquals("9a032422711082db2987259256de7d2e114754af8694c85ac241cb72a6245fc6998245a1a4e5ea2cfa0803e7bcd1d483274c45cc09c027edc83be75433aee2730ec03d10e13f8c292369b98e971024b4f100389934a1c184e5526594b6930d9f4a393d4dbc4a3591b25caf4eaecb28d75dadae9d51c67d704284b33672865183631a486b8fc29bb93431c39c6c09dd5745116c72e9d2df5da11d30769bd836d1129ccbf28dbd1929cd2c6f7ac934e7c57e66f13e612524baa08af6fb908596d082bbc2bd6957c4383030753cad6eb4f4315d7815156474a7f88ce6c4c53677d0066a61a9f831c37d279e71ce5eba39114cd09f7f14177aebff510a5833d48c6067f29a69a59ec43050bcc46fecf74d03d9eca5327cd6ae48c1281db75a2217d365f72633e1bda290e6660a805eb82bd115dbd3a9eb8132aee9c90a4d12f3e2a064d3ad337b7c480fd999fea107f47d59a13e68bd5234bdec5a584873997ff129655733f37f227eb24fcc6c5d8cb6b59ede61470b98efb437b69c4792d42e59b298b7baceed7a31ac372d9584dffdb8bbb557f853a0a5a45027e8812d5caf809bfb27110aa5a1e9269b381a9978e7c33e1a67969310042e7429d5e133661b3c579c76bac0483408cc43b8e5148fc97633805804a1bab3989c9b2e1e03d57634beeada085d37b1f48db0f4059437c464e2d21c7cc002688d947ceba3edabf68dc2e5ba03009f30eca3298071e1ae7cd9da6e9c0100bb45de187422281df159a8b75490b73632fe5f4f0294eb930d87902bca290c6e281e45d2d307df30aa2c8ac6c826693aa1ecda01d3793d7690e2d20f8d03d1796401302597aafd726702bc44c0dfc6df843b2b9e683fa31a3816340c798037286922c2f03e45b647fff75cafa7e6d9b6c25f5906954f3b252ecd7a540d357b529e5667e2785b8e39fb6031ff2f0bb724b27e4e397d8dda0bc6a8771212d115317538ae4677e205b5da2e7fa65b60942a27ccfba2a6b1aace8b0c3bf119f1cc98aa7ae429436b8881f71df6d9e6a78d2b40835a02b3e5aae5127422e3f7ebaf0c7978b415691daea7c3a4d0c37eb9aa74384d6f70788912fd97cff660a7fbb2686c08c743823449e15335529294af4083e860f1c46db147e22bcaac72304583eea46ffada59df72f33b4b919e21c1085764be34d2c94bed1b5fd1688bf5da393230b48688c938b59b899e86a397454aa5b05ee2a2f5e7f9d9daf56295a7b98eea751c3ddb919bc2236be0725cbf88f093691982794052c42f4e7d25a17c4fe5b68aa14c00ba62edbc1c6b3fd492e25d6ec1c254ffb46e264dd15ee2a6353d34e461647bf3c03ee8d9987bd5dd920bab36fc4b1ce860bb255ffc552a415667b6d0fadb9d9fba3e67bccdf43ee938a2b41b088e248a8cf799c1b91eabfc7ef931184cfbe1b7dc943f853eb2010a6376232a14d3fe30cf91bdcf5a6e0c424cf52c4b39a64ff94ebfac3b530fa12e8a8eb69f8485bc09e2027816aa5909680201b17a2a42ae02bed1740c85cb4b67b42c1c1527460a8b2412596d49092e08a39c02ab7bf776262086edbae89bc2b68ef5937ed82b4bc5428e53507223e3f132a011a9596f0dbf13e619cac32af36eb30ff9fd2b5a437c1dcc7532726dcbb89ad83857d1fa578759444872f1fbb745475954b3eeb334acb3a4a7d13220f6b2ff092df2c2b060f0585090c9e11de7f8f8a6f39908e07afd653b24a45a0b6ae9268493170acbaaf18f87d2b94b63808b6ff875c3f495c639adde5bbbcb50789768dd51dc1e8380dc2758a471b66a4fc0c45555c2f14a0aaf7361447eb6b1e26e7a2ef138cf4831870b1c3ccece07d1943beecc4d19684340ba7989286d4bd989fa12e45cdc0a6e14fde46358a40663f1ca36935ff03fd553534dce1a67e8e6d5dd3339dcb4a1f935cb5c2af7be1284663e6701e5819478cb9226bb0a6fc23ad8d9c5c4561aa547637b297caef29a65cd4086ad6143f08e7ff7c30a8e85cfc7cbec7283bb08174e191f5cd5b3a22e6bfe6116c1765eb483bb6af2ea3ac4548c89b1343643c4d990a527a3d12c6aa594833babc82ff40a0a087c7adf74b168c2d41ca155ba2d73939c4e324eef6889f9ad5e8bf85c37005c449a8040afe11358b0e1fb7fa4313e5fa8573cd5675ce9576707193809045ab33e7d0bdd7fc77de52d93c16560c89ee0e7b0cc232f957380f60bf3a1e5f48e13be72b778e5538d739f28b75b8d66d477490018833ee9673e3b2258abbd31c8ce5c000d2e63e38f1dd53cee4f3029323fefa7dd8be5652dd0528c4c86d34bc02beb30134b590e13402520f6000dbb62ed4ef4a7f4b3f01399b8d9225288dd407e15253724b9286c3585fe20e12f16ca1ad9e0bdce75e3c060eb63b890b73b2a0c467e5c8d558b9918af163aa957de19c424e76c7af760f7bcf8ad3ff3f604691bf6e689719252734a8456ba574c6de298bc53a9546418f7e8cc29e530eecb10e1f5f3152b159b4e492563e3f03186af75c8eacb9e058dc0e6aba9addf37484bb41b4048d9ffeb6b2e047b72ded269015fd12897abbdcf4dbabc02324c56d72aa39a84671c702a4c5246ddd450f5225fc31f7051ee76351d39e6ac0b664ac9c1190f40a37c39f0a2be610291bcaf09361e7914f18cdc8c956677147f90cecb07fc6a6f8e4b46ef941e2cd0cad0c5770e28c2dd37faca1831a3fee6cba6db9269b33d31e49dfefd52d1b55ded815d8e2de9245c884a6fedfd9191284d05710d5715e92aee1dba046b393242989e69dcca85b3ad650e0f6c22daa313c3559c02f4a62daf27ffe1ee0b6ac739a13a84d7aabf1a0c5e0b35151f3d85636345a3b648db9edc4d210503918b23a4c244709b18e63ac2e030f8973d504a0b2dea9483df577b7be130dc9568f8ad43fba8d77a0cd636d2a4117f5355225c05cafc86ca2babdfe7f4d191238693ac9f0a1572e439a1d7df904e9b01ec8422f8aa0494ccdf1f6b7509dd492cc8f575ed66608294125975e048be1a11641f99", toString(publicKey.toByteArray()));

        WOTSPlusSignature wotsPlusSignature = wotsPlus.signDigest(digest, otsAddress);
        assertEquals("843ed20395d6f2a233e3dd54f2d4d69d71b65b3bc4a61b590bdbd44538ae6e5a5e5482065fe24929dbf96b89c7270543c56a634ef3e3f246c8961b2239161b2fdff0be97ab727e1b17ad43280254600424cd052e3a34bfec2e45653632c76439b1b5beb9b2090d2bdee33d807e735a5671b3e204d77d9c13092cb3de94b9683777bded33a2f32c55bb63863ce91b145ac4b218c5faba18465f4af9a6fe5f29be8e73afdd16b072943ecb6b166b7e6cccd5700c1a6543f7a1e7badefca63b414f346eabf850647a13ca49b973a0fa33db7152627899814e27f08f4f71d3e6891c6af040c3670b68911ec65cb9c1807b78fefbf04edf32c98ffce9a71106f283a23b132e3c464d8e1be7fa82fd5960c8f28b1640d635cbf7d46049907839f830ab92f24b8fc960c8ab387b5cd1bb2c9ccbbee7315d889edd1664321ba6964f2806c28734985515f1990352a6065046f7c87bbcf56c901d461180883e0948f5477996872063b7ff147b07b1c3c1d56457a2e96ca6bc57b10779daa8925bd890ddfcf433ee2380106445d95e028315fb98e958262e6c9f981b9b95efd1e39eba5490c0819552944073ea2c4340d8325bbbbc591bda8badbcc21a1a432c614652dc7ddd81c8ff400c9f07c4734dc47e3c496aafdf278517cf95b212247c90891716edfffa71189848455d0376c409f6f6ad4c1ccf123f52b5a3323b4f21e7fea04e7c4df7916cfb30def566969532ebb0eb5aa5afe65a96d54356437cdf12c86cd9d87c793e8b3336dda6b75b7aa6981cfdcc8cd2816818eec41f697fdc2ac521d75390dddcae8753b7da7707640c5b0c66f0f980ed2ed3e578423789e8c43e2aaef28e47dc098526deeb04f05b2a377121bfdad3e08c3271b196b64c64e73ce6565772d04d6bc758c3c0fc1d674fef8c02aef6b0162e0e6e14c5f9633cef39fb305a8b35c0b3a92083f5d2e28af40931916b80971e3932a19e412de8ece27eb72015238291c68184512ab2bcf7d9258acc73a6486a4c161fe7d4884c5bf2139011e9882d82d3ebd449ec634c4410882157d66df543e4f0aa91888b200f6e1d581b62b66387bc77dcdd41d288c5770abf2ffbc54984d726cb96f35847ff888472c0d23b652b18fc69ed6bcfe181746fb07ac660d68bb9a73413f2de0895dceca7e86037ebb6001a7a2c6976f00d4dcd90a711b9c3656cf08fae88c07521152e9ef539c8c37cb94594b9c013af06509eabc8268f389f6ed19659d171fd058f0da76a0efc5e1f80b01ddf5f8225ee6fe2d64c2296df049ace60d4d742c34dd9eb6b9265d9159e83188cb0f216cc76d6d2c26333d15fd19ef236783d5a6959ac0d200c4260aad93b186dc795c4f4994958379551a0e9503258d9f8b76334a2eb4cb89bbe1af37e36cb8e18ebb2bb21bad8f9742ab598fd79fa15baf738cac391182acc9623afcd548c878e45cedd2fb5ebb3f588a125bc4a517c2394e7b0acac663eafcfe68de7272185b62cd9eef16697f089e438e73d627b6e05e89c99c24a3deeaef0d233b22b64a17a54a91597245064e9352239575aab48d1262caca41f9cba57997b454d4c47376c1477130c24187b0cc6c3a6283cfaed91f44868dffa431604568f6df9b72964b7808edf68152bf783c6250f9f54d279fb3df5318fe748a8612cd4742644d40489fbea800d0a1b9ae65a43fe86a2311517323fe33a83aa34fab2debc36ef97c151c941a9398ef6162cd6c2c3fd966c9bdee039fc001e36166c0796345d12252b6d1bd444b3d65b89b962a63a56733fe3350cff0e62219d892adc0da398673ed6f0801ac23e245ba4337dbad6e18ca6d5c896783d5b3f375972601e0f829adead7b8ca5b01ada6d45eaab119ef07ac07107736f56272bc9c70632e3941ae87cdef487b2d05befd4d1f433b6cc878241251bd3d0d086e983c34bc10a958da9bc6dc1602b2ad7d0095a60b2e3de6176428ccb3db4135531aa24f0a9d3419dfef273582ae77b8a3e73deb702e52f3581ff2062c0b7409e8306c0a2f52a4635936c618a8b46529d1a175661d30a5bb0eaf16db72e07b40817843a8403d52390bad29e9863007f0a3679ce2ac9be58c097ee80d24a6682320aff66a9a63fb04ffd237aab09474804fe6b54c87b98a57700e7d27442ae664e42a466c7f4163e22571615a7d6e0ce442caf6099d3159411a8ba82ba58b8a8ffe22c4727c73c3b0e18801fd4ab382e196d851ad86bddca7035441b36b7eed4ee6bc9e962d6bf3016623e554c72aa3fc356f293e5b0816eeaac445b5225b7c3d2f3a99aa7278efd5a4627b15f162a3183465223487342a1eca946b3d143be407229343b096031905e0e914f668721aa2b3200409992b270f2f1b2c329530cbf069bbcc361139940d8d40ad2de3ecb2c78f3be8afc3a451d00ef206a5b2d41326a8690713a7b4f47835dad1373039653914eefd7d758c377928fcad4f15f9b14f71786c85f1d1804cd180eb5816cdc4fb5f92f15b1a0851a722b77eedb6d2e480001ac124e28624d769ad3ca7587809af6f47e0523b19581f53601b49c713c9639ca5a3a382ae3fb900beba7a8b7b97d048532aeea133a778bde4398bc39e6b2a6c37f5f05e9fcb154d96601b30fcd64c75da2017001779d2a2efff1975563342a1bc970603189dad4c978cd2c76bda6b0699f78009a9e3dc5af5d918f33e2383fe4b5d4280a5af2d9cab7351d8f5ea055978193878fd7921cdc0d786cdea87fdf7f7f7feabb36be1110bcfb38c164a81785f3fabc7f66b8b984fec33482729b62b3dec8411dd4781620a07c5019f105291359bf6dc2ebbae1dd090286c3f30d97bd7dfbc4c54dc9f810f9e6782e2fb98158e81f426f248bcbbfdf2437c5a7191482ccdaa447667eed07e7e4ca77d8598965c2df41d849e428a9945c4c556dde415f4e45c367e8e1283e97dcad22841357ad5a6e9a338ffaab742c08423cf416d714e2852e114e640939babb5c87557e73c6eaed4529d6ea3461f8bd7fa0d3b47cca349231a4", toString(wotsPlusSignature.toByteArray()));

        WOTSPlusPublicKeyParameters publicKeyFromSignature = wotsPlus.getPublicKeyFromSignature(digest, wotsPlusSignature, otsAddress);

        assertEquals(toString(publicKey.toByteArray()), toString(publicKeyFromSignature.toByteArray()));
    }

    private String toString(byte[][] data) {
        StringBuilder s = new StringBuilder();
        for (byte[] l : data) {
            s.append(Hex.toHexString(l));
        }
        return s.toString();
    }
}