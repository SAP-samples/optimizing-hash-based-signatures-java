package org.example.bcpqc.pqc.crypto.xmss;

import org.example.bcpqc.experiments.hashing.HashingProviderProvider;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

class BDSHelper {
    final int treeHeight;
    final int k;
    final WOTSPlusParameters wotsPlusParameters;
    final byte[] publicSeed;
    final byte[] secretSeed;
    final OTSHashAddress otsHashAddress;

    public BDSHelper(int treeHeight, int k, WOTSPlusParameters wotsPlusParameters, byte[] publicSeed, byte[] secretSeed, OTSHashAddress otsHashAddress) {
        this.treeHeight = treeHeight;
        this.k = k;
        this.wotsPlusParameters = wotsPlusParameters;
        this.publicSeed = publicSeed;
        this.secretSeed = secretSeed;
        this.otsHashAddress = otsHashAddress;
    }

    BDSStateFragment initialize() {
        if (HashingProviderProvider.EXECUTE_PARALLEL) {
            return this.initializeParallel();
        } else {
            return this.initializeSequential();
        }
    }

    BDSStateFragment initializeSequential() {
        return initializeSegment(this.treeHeight, 0);
    }

    BDSStateFragment initializeParallel() {
        // Pick largest power of two <= cpuCount as segmentCount - TODO does this make sense?
        int sequentialHeight = (int) (Math.log(Runtime.getRuntime().availableProcessors()) / Math.log(2));
        int segmentHeight = treeHeight - sequentialHeight;
        if (segmentHeight <= 0) {
            return initializeSequential();
        }
        int segmentCount = 1 << sequentialHeight;

        System.out.println("Running key generation with " + segmentCount + " segments");

        List<BDSStateFragment> fragments = IntStream.range(0, segmentCount)
                .parallel()
                .mapToObj(i -> initializeSegment(segmentHeight, i))
                .collect(Collectors.toList());

        BDSStateFragment merged = mergeFragments(fragments, segmentHeight);
        return merged;
    }

    private BDSStateFragment mergeFragments(List<BDSStateFragment> fragments, int segmentHeight) {
        BDSStateFragment state = new BDSStateFragment();

        // Merge authentication path
        state.authenticationPath = fragments.get(0).authenticationPath;

        for (BDSStateFragment f : fragments) {
            // Merge retain lists
            if (state.retain.isEmpty()) {
                state.retain = f.retain;
            } else {
                for (Integer key : f.retain.keySet()) {
                    if (state.retain.get(key) == null) {
                        state.retain.put(key, f.retain.get(key));
                    } else {
                        state.retain.get(key).addAll(f.retain.get(key));
                    }
                }
            }

            // Merge tree hash instances
            for (int i = 0; i < state.treeHashInstances.size(); i++) {
                if (f.treeHashInstances.get(i).getTailNode() != null) {
                    if (state.treeHashInstances.get(i).getTailNode() != null) {
                        throw new IllegalArgumentException("Tree hash instance already has node set");
                    }
                    state.treeHashInstances.get(i).setNode(f.treeHashInstances.get(i).getTailNode());
                }
            }
        }

        Stack<XMSSNode> stack = new Stack<>();
        HashTreeAddress hashTreeAddress = (HashTreeAddress) new HashTreeAddress.Builder().withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress()).build();
        WOTSPlus wotsPlus = new WOTSPlus(wotsPlusParameters);
        // Import public seed
        wotsPlus.importKeys(new byte[wotsPlusParameters.getTreeDigestSize()], publicSeed);
        for (int i = 0; i < fragments.size(); i++) {
            XMSSNode node = fragments.get(i).root;

            hashTreeAddress = (HashTreeAddress) new HashTreeAddress.Builder()
                    .withLayerAddress(hashTreeAddress.getLayerAddress())
                    .withTreeAddress(hashTreeAddress.getTreeAddress())
                    .withTreeIndex(i)
                    .withTreeHeight(segmentHeight)
                    .withKeyAndMask(hashTreeAddress.getKeyAndMask()).build();
            while (!stack.isEmpty() && stack.peek().getHeight() == node.getHeight()) {
                int indexOnHeight = hashTreeAddress.getTreeIndex();

                /* add to authenticationPath if leafIndex == 1 */
                if (indexOnHeight == 1) {
                    state.authenticationPath.add(node);
                }
                /* store next right authentication node */
                if (indexOnHeight == 3 && node.getHeight() < (treeHeight - k)) {
                    state.treeHashInstances.get(node.getHeight()).setNode(node);
                }
                if (indexOnHeight >= 3 && (indexOnHeight & 1) == 1 && node.getHeight() >= (treeHeight - k) && node.getHeight() <= (treeHeight - 2)) {
                    if (state.retain.get(node.getHeight()) == null) {
                        LinkedList<XMSSNode> queue = new LinkedList<XMSSNode>();
                        queue.add(node);
                        state.retain.put(node.getHeight(), queue);
                    } else {
                        state.retain.get(node.getHeight()).add(node);
                    }
                }
                hashTreeAddress = (HashTreeAddress) new HashTreeAddress.Builder()
                        .withLayerAddress(hashTreeAddress.getLayerAddress())
                        .withTreeAddress(hashTreeAddress.getTreeAddress())
                        .withTreeHeight(hashTreeAddress.getTreeHeight())
                        .withTreeIndex((hashTreeAddress.getTreeIndex() - 1) / 2)
                        .withKeyAndMask(hashTreeAddress.getKeyAndMask()).build();
                node = XMSSNodeUtil.randomizeHash(wotsPlus, stack.pop(), node, hashTreeAddress);
                node = new XMSSNode(node.getHeight() + 1, node.getValue());
                hashTreeAddress = (HashTreeAddress) new HashTreeAddress.Builder()
                        .withLayerAddress(hashTreeAddress.getLayerAddress())
                        .withTreeAddress(hashTreeAddress.getTreeAddress())
                        .withTreeHeight(hashTreeAddress.getTreeHeight() + 1)
                        .withTreeIndex(hashTreeAddress.getTreeIndex())
                        .withKeyAndMask(hashTreeAddress.getKeyAndMask()).build();
            }
            /* push to stack */
            stack.push(node);
        }
        state.root = stack.pop();
        return state;
    }

    private BDSStateFragment initializeSegment(int segmentHeight, int segment) {
        BDSStateFragment state = new BDSStateFragment();
        Stack<XMSSNode> stack = new Stack<>();


        if (otsHashAddress == null) {
            throw new NullPointerException("otsHashAddress == null");
        }
        /* prepare addresses */
        LTreeAddress lTreeAddress = (LTreeAddress) new LTreeAddress.Builder()
                .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
                .build();
        HashTreeAddress hashTreeAddress = (HashTreeAddress) new HashTreeAddress.Builder()
                .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
                .build();

        /* iterate indexes */
        int leafsPerSegment = 1 << segmentHeight;
        for (int indexLeaf = leafsPerSegment * segment; indexLeaf < leafsPerSegment * (segment + 1); indexLeaf++) {
            /* generate leaf */
            OTSHashAddress otsHashAddress = (OTSHashAddress) new OTSHashAddress.Builder()
                    .withLayerAddress(this.otsHashAddress.getLayerAddress()).withTreeAddress(this.otsHashAddress.getTreeAddress())
                    .withOTSAddress(indexLeaf).withChainAddress(this.otsHashAddress.getChainAddress())
                    .withHashAddress(this.otsHashAddress.getHashAddress()).withKeyAndMask(this.otsHashAddress.getKeyAndMask())
                    .build();
            /*
             * import WOTSPlusSecretKey as its needed to calculate the public
             * key on the fly
             */
            WOTSPlus wotsPlus = new WOTSPlus(wotsPlusParameters);
            wotsPlus.importKeys(wotsPlus.getWOTSPlusSecretKey(secretSeed, otsHashAddress), publicSeed);
            WOTSPlusPublicKeyParameters wotsPlusPublicKey = wotsPlus.getPublicKey(otsHashAddress);
            lTreeAddress = (LTreeAddress) new LTreeAddress.Builder().withLayerAddress(lTreeAddress.getLayerAddress()).withTreeAddress(lTreeAddress.getTreeAddress()).withLTreeAddress(indexLeaf).withTreeHeight(lTreeAddress.getTreeHeight()).withTreeIndex(lTreeAddress.getTreeIndex()).withKeyAndMask(lTreeAddress.getKeyAndMask()).build();
            XMSSNode node = XMSSNodeUtil.lTree(wotsPlus, wotsPlusPublicKey, lTreeAddress);

            hashTreeAddress = (HashTreeAddress) new HashTreeAddress.Builder().withLayerAddress(hashTreeAddress.getLayerAddress()).withTreeAddress(hashTreeAddress.getTreeAddress()).withTreeIndex(indexLeaf).withKeyAndMask(hashTreeAddress.getKeyAndMask()).build();
            while (!stack.isEmpty() && stack.peek().getHeight() == node.getHeight()) {
                /* add to authenticationPath if leafIndex == 1 */
                int indexOnHeight = indexLeaf / (1 << node.getHeight());
                if (indexOnHeight == 1) {
                    state.authenticationPath.add(node);
                }
                /* store next right authentication node */
                if (indexOnHeight == 3 && node.getHeight() < (treeHeight - k)) {
                    state.treeHashInstances.get(node.getHeight()).setNode(node);
                }
                if (indexOnHeight >= 3 && (indexOnHeight & 1) == 1 && node.getHeight() >= (treeHeight - k) && node.getHeight() <= (treeHeight - 2)) {
                    if (state.retain.get(node.getHeight()) == null) {
                        LinkedList<XMSSNode> queue = new LinkedList<XMSSNode>();
                        queue.add(node);
                        state.retain.put(node.getHeight(), queue);
                    } else {
                        state.retain.get(node.getHeight()).add(node);
                    }
                }
                hashTreeAddress = (HashTreeAddress) new HashTreeAddress.Builder().withLayerAddress(hashTreeAddress.getLayerAddress()).withTreeAddress(hashTreeAddress.getTreeAddress()).withTreeHeight(hashTreeAddress.getTreeHeight()).withTreeIndex((hashTreeAddress.getTreeIndex() - 1) / 2).withKeyAndMask(hashTreeAddress.getKeyAndMask()).build();
                node = XMSSNodeUtil.randomizeHash(wotsPlus, stack.pop(), node, hashTreeAddress);
                node = new XMSSNode(node.getHeight() + 1, node.getValue());
                hashTreeAddress = (HashTreeAddress) new HashTreeAddress.Builder().withLayerAddress(hashTreeAddress.getLayerAddress()).withTreeAddress(hashTreeAddress.getTreeAddress()).withTreeHeight(hashTreeAddress.getTreeHeight() + 1).withTreeIndex(hashTreeAddress.getTreeIndex()).withKeyAndMask(hashTreeAddress.getKeyAndMask()).build();
            }
            /* push to stack */
            stack.push(node);
        }
        state.root = stack.pop();
        return state;
    }

    class BDSStateFragment {
        List<XMSSNode> authenticationPath = new ArrayList<XMSSNode>();
        Map<Integer, LinkedList<XMSSNode>> retain = new TreeMap<Integer, LinkedList<XMSSNode>>();
        List<BDSTreeHash> treeHashInstances = new ArrayList<BDSTreeHash>();
        XMSSNode root;

        BDSStateFragment() {
            for (int height = 0; height < (treeHeight - k); height++) {
                treeHashInstances.add(new BDSTreeHash(height));
            }
        }
    }
}
