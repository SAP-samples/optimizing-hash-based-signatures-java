package org.example.bcpqc.pqc.crypto.xmss;

import java.lang.reflect.Array;

public class PRFCacheHashMap<T> {
    private final Class<?> type;
    private T[] states;
    private int[] addressParts = new int[1024];
    private int add_count = 0;

    public PRFCacheHashMap(Class<?> type) {
        this.type = type;
        states = (T[]) Array.newInstance(type, 1024);
    }

    private int buildAddressPart(byte[] key) {
        return (key[2] & 0xFF) + ((key[key.length / 2] & 0xFF) << 8) + ((key[key.length - 1] & 0xFF) << 16);
    }

    private int buildMapKey(byte[] key) {
        return (key[0] & 0xFF) + ((key[1] & 0b11) << 8);
    }

    public void add(byte[] key, T state) {
        int map_key = buildMapKey(key);
        states[map_key] = state;
        addressParts[map_key] = buildAddressPart(key);
        //add_count++;
        //System.out.println("PRF states added to cache: " + add_count);
    }

    public T get(byte[] key) {
        int map_key = buildMapKey(key);
        if (addressParts[map_key] == buildAddressPart(key)) {
            return states[map_key];
        }
        return null;
    }
}
