package com.doumsg;

import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class EcdhKeyFactorySpi extends KeyFactorySpi.ECDH {
    @Override
    public PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        return super.engineGeneratePublic(keySpec);
    }

    @Override
    public PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        return super.engineGeneratePrivate(keySpec);
    }
}

