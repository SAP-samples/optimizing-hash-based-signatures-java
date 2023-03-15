package org.example.bcpqc.pqc.jcajce.interfaces;

import org.example.bcpqc.pqc.jcajce.spec.SPHINCSPlusParameterSpec;

import java.security.Key;


public interface SPHINCSPlusKey
        extends Key {
    /**
     * Return the parameters for this key.
     *
     * @return a SPHINCSPlusParameterSpec
     */
    SPHINCSPlusParameterSpec getParameterSpec();
}
