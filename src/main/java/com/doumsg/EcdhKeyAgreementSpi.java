package com.doumsg;

import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyAgreementSpi;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;

public class EcdhKeyAgreementSpi extends KeyAgreementSpi.DH {
    @Override
    public void engineInit(Key key, SecureRandom secureRandom) throws InvalidKeyException {
        super.engineInit(key, secureRandom);
    }

    @Override
    public Key engineDoPhase(Key key, boolean b) throws InvalidKeyException, IllegalStateException {
        return super.engineDoPhase(key, b);
    }

    @Override
    public byte[] engineGenerateSecret() throws IllegalStateException {
        return super.engineGenerateSecret();
    }
}
