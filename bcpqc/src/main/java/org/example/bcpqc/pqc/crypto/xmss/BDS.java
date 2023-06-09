package org.example.bcpqc.pqc.crypto.xmss;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.*;

/**
 * BDS.
 */
public final class BDS
        implements Serializable {
    private static final long serialVersionUID = 1L;

    private transient WOTSPlus wotsPlus;

    private final int treeHeight;
    private List<BDSTreeHash> treeHashInstances;
    private int k;
    private XMSSNode root;
    private List<XMSSNode> authenticationPath;
    private Map<Integer, LinkedList<XMSSNode>> retain;
    private Stack<XMSSNode> stack;

    private Map<Integer, XMSSNode> keep;
    private int index;
    private boolean used;

    private transient int maxIndex;

    /**
     * Place holder BDS for when state is exhausted.
     *
     * @param params tree parameters
     * @param index  the index that has been reached.
     */
    BDS(XMSSParameters params, int maxIndex, int index) {
        this(params.getWOTSPlus(), params.getHeight(), params.getK(), index);
        this.maxIndex = maxIndex;
        this.index = index;
        this.used = true;
    }

    /**
     * Set up constructor.
     *
     * @param params         tree parameters
     * @param publicSeed     public seed for tree
     * @param secretKeySeed  secret seed for tree
     * @param otsHashAddress hash address
     */
    BDS(XMSSParameters params, byte[] publicSeed, byte[] secretKeySeed, OTSHashAddress otsHashAddress) {
        this(params.getWOTSPlus(), params.getHeight(), params.getK(), ((1 << params.getHeight()) - 1));
        this.initialize(publicSeed, secretKeySeed, otsHashAddress);
    }

    private void initialize(byte[] publicSeed, byte[] secretKeySeed, OTSHashAddress otsHashAddress) {
        BDSHelper helper = new BDSHelper(treeHeight, k, wotsPlus.getParams(), publicSeed, secretKeySeed, otsHashAddress);
        BDSHelper.BDSStateFragment state = helper.initialize();
        this.authenticationPath = state.authenticationPath;
        this.root = state.root;
        this.retain = state.retain;
        this.treeHashInstances = state.treeHashInstances;
    }

    /**
     * Set up constructor for a tree where the original BDS state was lost.
     *
     * @param params         tree parameters
     * @param publicSeed     public seed for tree
     * @param secretKeySeed  secret seed for tree
     * @param otsHashAddress hash address
     * @param index          index counter for the state to be at.
     */
    BDS(XMSSParameters params, byte[] publicSeed, byte[] secretKeySeed, OTSHashAddress otsHashAddress, int index) {
        this(params.getWOTSPlus(), params.getHeight(), params.getK(), ((1 << params.getHeight()) - 1));

        this.initialize(publicSeed, secretKeySeed, otsHashAddress);

        while (this.index < index) {
            this.nextAuthenticationPath(publicSeed, secretKeySeed, otsHashAddress);
            this.used = false;
        }
    }

    private BDS(WOTSPlus wotsPlus, int treeHeight, int k, int maxIndex) {
        this.wotsPlus = wotsPlus;
        this.treeHeight = treeHeight;
        this.maxIndex = maxIndex;
        this.k = k;
        if (k > treeHeight || k < 2 || ((treeHeight - k) % 2) != 0) {
            throw new IllegalArgumentException("illegal value for BDS parameter k");
        }
        authenticationPath = new ArrayList<XMSSNode>();
        retain = new TreeMap<Integer, LinkedList<XMSSNode>>();
        stack = new Stack<XMSSNode>();

        treeHashInstances = new ArrayList<BDSTreeHash>();
        for (int height = 0; height < (treeHeight - k); height++) {
            treeHashInstances.add(new BDSTreeHash(height));
        }

        keep = new TreeMap<Integer, XMSSNode>();
        index = 0;
        this.used = false;
    }

    BDS(BDS last) {
        this.wotsPlus = new WOTSPlus(last.wotsPlus.getParams());
        this.treeHeight = last.treeHeight;
        this.k = last.k;
        this.root = last.root;
        this.authenticationPath = new ArrayList<XMSSNode>();  // note use of addAll to avoid serialization issues
        this.authenticationPath.addAll(last.authenticationPath);
        this.retain = new TreeMap<Integer, LinkedList<XMSSNode>>();
        for (Iterator it = last.retain.keySet().iterator(); it.hasNext(); ) {
            Integer key = (Integer) it.next();
            this.retain.put(key, (LinkedList<XMSSNode>) last.retain.get(key).clone());
        }
        this.stack = new Stack<XMSSNode>(); // note use of addAll to avoid serialization issues
        this.stack.addAll(last.stack);
        this.treeHashInstances = new ArrayList<BDSTreeHash>();
        for (Iterator it = last.treeHashInstances.iterator(); it.hasNext(); ) {
            this.treeHashInstances.add(((BDSTreeHash) it.next()).clone());
        }
        this.keep = new TreeMap<Integer, XMSSNode>(last.keep);
        this.index = last.index;
        this.maxIndex = last.maxIndex;
        this.used = last.used;
    }

    private BDS(BDS last, byte[] publicSeed, byte[] secretKeySeed, OTSHashAddress otsHashAddress) {
        this.wotsPlus = new WOTSPlus(last.wotsPlus.getParams());
        this.treeHeight = last.treeHeight;
        this.k = last.k;
        this.root = last.root;
        this.authenticationPath = new ArrayList<XMSSNode>();  // note use of addAll to avoid serialization issues
        this.authenticationPath.addAll(last.authenticationPath);
        this.retain = new TreeMap<Integer, LinkedList<XMSSNode>>();
        for (Iterator it = last.retain.keySet().iterator(); it.hasNext(); ) {
            Integer key = (Integer) it.next();
            this.retain.put(key, (LinkedList<XMSSNode>) last.retain.get(key).clone());
        }
        this.stack = new Stack<XMSSNode>(); // note use of addAll to avoid serialization issues
        this.stack.addAll(last.stack);
        this.treeHashInstances = new ArrayList<BDSTreeHash>();
        for (Iterator it = last.treeHashInstances.iterator(); it.hasNext(); ) {
            this.treeHashInstances.add(((BDSTreeHash) it.next()).clone());
        }
        this.keep = new TreeMap<Integer, XMSSNode>(last.keep);
        this.index = last.index;
        this.maxIndex = last.maxIndex;
        this.used = false;

        this.nextAuthenticationPath(publicSeed, secretKeySeed, otsHashAddress);
    }


    private BDS(BDS last, int maxIndex, WOTSPlusParameters wotsPlusParameters) {
        this.wotsPlus = new WOTSPlus(wotsPlusParameters);
        this.treeHeight = last.treeHeight;
        this.k = last.k;
        this.root = last.root;
        this.authenticationPath = new ArrayList<XMSSNode>();  // note use of addAll to avoid serialization issues
        this.authenticationPath.addAll(last.authenticationPath);
        this.retain = new TreeMap<Integer, LinkedList<XMSSNode>>();
        for (Iterator it = last.retain.keySet().iterator(); it.hasNext(); ) {
            Integer key = (Integer) it.next();
            this.retain.put(key, (LinkedList<XMSSNode>) last.retain.get(key).clone());
        }
        this.stack = new Stack<XMSSNode>();     // note use of addAll to avoid serialization issues
        this.stack.addAll(last.stack);
        this.treeHashInstances = new ArrayList<BDSTreeHash>();
        for (Iterator it = last.treeHashInstances.iterator(); it.hasNext(); ) {
            this.treeHashInstances.add(((BDSTreeHash) it.next()).clone());
        }
        this.keep = new TreeMap<Integer, XMSSNode>(last.keep);
        this.index = last.index;
        this.maxIndex = maxIndex;
        this.used = last.used;
        this.validate();
    }

    public BDS getNextState(byte[] publicSeed, byte[] secretKeySeed, OTSHashAddress otsHashAddress) {
        return new BDS(this, publicSeed, secretKeySeed, otsHashAddress);
    }


    private void nextAuthenticationPath(byte[] publicSeed, byte[] secretSeed, OTSHashAddress otsHashAddress) {
        if (otsHashAddress == null) {
            throw new NullPointerException("otsHashAddress == null");
        }
        if (used) {
            throw new IllegalStateException("index already used");
        }
        if (index > maxIndex - 1) {
            throw new IllegalStateException("index out of bounds");
        }

        /* determine tau */
        int tau = XMSSUtil.calculateTau(index, treeHeight);
        /* parent of leaf on height tau+1 is a left node */
        if (((index >> (tau + 1)) & 1) == 0 && (tau < (treeHeight - 1))) {
            keep.put(tau, authenticationPath.get(tau));
        }

        /* prepare addresses */
        LTreeAddress lTreeAddress = (LTreeAddress) new LTreeAddress.Builder()
                .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
                .build();
        HashTreeAddress hashTreeAddress = (HashTreeAddress) new HashTreeAddress.Builder()
                .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
                .build();

        /* leaf is a left node */
        if (tau == 0) {
            otsHashAddress = (OTSHashAddress) new OTSHashAddress.Builder()
                    .withLayerAddress(otsHashAddress.getLayerAddress()).withTreeAddress(otsHashAddress.getTreeAddress())
                    .withOTSAddress(index).withChainAddress(otsHashAddress.getChainAddress())
                    .withHashAddress(otsHashAddress.getHashAddress()).withKeyAndMask(otsHashAddress.getKeyAndMask())
                    .build();
            /*
             * import WOTSPlusSecretKey as its needed to calculate the public
             * key on the fly
             */
            wotsPlus.importKeys(wotsPlus.getWOTSPlusSecretKey(secretSeed, otsHashAddress), publicSeed);
            WOTSPlusPublicKeyParameters wotsPlusPublicKey = wotsPlus.getPublicKey(otsHashAddress);
            lTreeAddress = (LTreeAddress) new LTreeAddress.Builder().withLayerAddress(lTreeAddress.getLayerAddress())
                    .withTreeAddress(lTreeAddress.getTreeAddress()).withLTreeAddress(index)
                    .withTreeHeight(lTreeAddress.getTreeHeight()).withTreeIndex(lTreeAddress.getTreeIndex())
                    .withKeyAndMask(lTreeAddress.getKeyAndMask()).build();
            XMSSNode node = XMSSNodeUtil.lTree(wotsPlus, wotsPlusPublicKey, lTreeAddress);
            authenticationPath.set(0, node);
        } else {
            /* add new left node on height tau to authentication path */
            hashTreeAddress = (HashTreeAddress) new HashTreeAddress.Builder()
                    .withLayerAddress(hashTreeAddress.getLayerAddress())
                    .withTreeAddress(hashTreeAddress.getTreeAddress()).withTreeHeight(tau - 1)
                    .withTreeIndex(index >> tau).withKeyAndMask(hashTreeAddress.getKeyAndMask()).build();
            /*
             * import WOTSPlusSecretKey as its needed to calculate the public
             * key on the fly
             */
            wotsPlus.importKeys(wotsPlus.getWOTSPlusSecretKey(secretSeed, otsHashAddress), publicSeed);
            XMSSNode node = XMSSNodeUtil.randomizeHash(wotsPlus, authenticationPath.get(tau - 1), keep.get(tau - 1), hashTreeAddress);
            node = new XMSSNode(node.getHeight() + 1, node.getValue());
            authenticationPath.set(tau, node);
            keep.remove(tau - 1);

            /* add new right nodes to authentication path */
            for (int height = 0; height < tau; height++) {
                if (height < (treeHeight - k)) {
                    authenticationPath.set(height, treeHashInstances.get(height).getTailNode());
                } else {
                    authenticationPath.set(height, retain.get(height).removeFirst());
                }
            }

            /* reinitialize treehash instances */
            int minHeight = Math.min(tau, treeHeight - k);
            for (int height = 0; height < minHeight; height++) {
                int startIndex = index + 1 + (3 * (1 << height));
                if (startIndex < (1 << treeHeight)) {
                    treeHashInstances.get(height).initialize(startIndex);
                }
            }
        }

        /* update treehash instances */
        for (int i = 0; i < (treeHeight - k) >> 1; i++) {
            BDSTreeHash treeHash = getBDSTreeHashInstanceForUpdate();
            if (treeHash != null) {
                treeHash.update(stack, wotsPlus, publicSeed, secretSeed, otsHashAddress);
            }
        }

        index++;
    }

    boolean isUsed() {
        return used;
    }

    void markUsed() {
        this.used = true;
    }

    private BDSTreeHash getBDSTreeHashInstanceForUpdate() {
        BDSTreeHash ret = null;
        for (BDSTreeHash treeHash : treeHashInstances) {
            if (treeHash.isFinished() || !treeHash.isInitialized()) {
                continue;
            }
            if (ret == null) {
                ret = treeHash;
                continue;
            }
            if (treeHash.getHeight() < ret.getHeight()) {
                ret = treeHash;
                continue;
            }
            if (treeHash.getHeight() == ret.getHeight()) {
                if (treeHash.getIndexLeaf() < ret.getIndexLeaf()) {
                    ret = treeHash;
                }
            }
        }
        return ret;
    }

    private void validate() {
        if (authenticationPath == null) {
            throw new IllegalStateException("authenticationPath == null");
        }
        if (retain == null) {
            throw new IllegalStateException("retain == null");
        }
        if (stack == null) {
            throw new IllegalStateException("stack == null");
        }
        if (treeHashInstances == null) {
            throw new IllegalStateException("treeHashInstances == null");
        }
        if (keep == null) {
            throw new IllegalStateException("keep == null");
        }
        if (!XMSSUtil.isIndexValid(treeHeight, index)) {
            throw new IllegalStateException("index in BDS state out of bounds");
        }
    }

    protected int getTreeHeight() {
        return treeHeight;
    }

    protected XMSSNode getRoot() {
        return root;
    }

    protected List<XMSSNode> getAuthenticationPath() {
        List<XMSSNode> authenticationPath = new ArrayList<XMSSNode>();

        for (XMSSNode node : this.authenticationPath) {
            authenticationPath.add(node);
        }
        return authenticationPath;
    }

    protected int getIndex() {
        return index;
    }

    public int getMaxIndex() {
        return maxIndex;
    }

    public BDS withWOTSDigest(WOTSPlusParameters params) {
        return new BDS(this, this.maxIndex, params);
    }

    public BDS withMaxIndex(int maxIndex, WOTSPlusParameters params) {
        return new BDS(this, maxIndex, params);
    }

    private void readObject(
            ObjectInputStream in)
            throws IOException, ClassNotFoundException {
        in.defaultReadObject();

        if (in.available() != 0) {
            this.maxIndex = in.readInt();
        } else {
            this.maxIndex = (1 << treeHeight) - 1;
        }
        if (maxIndex > ((1 << treeHeight) - 1) || index > (maxIndex + 1) || in.available() != 0) {
            throw new IOException("inconsistent BDS data detected");
        }
    }

    private void writeObject(
            ObjectOutputStream out)
            throws IOException {
        out.defaultWriteObject();

        out.writeInt(this.maxIndex);
    }
}
