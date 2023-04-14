package com.doumsg;


import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class NewEcdhCrypt {

    public static final String X509_SERVER_PUB_KEY = "3059301306072a8648ce3d020106082a8648ce3d03010703420004EBCA94D733E399B2DB96EACDD3F69A8BB0F74224E2B44E3357812211D2E62EFBC91BB553098E25E33A799ADC7F76FEB208DA7C6522CDB0719A305180CC54A82E";
    public static byte[] _g_share_key;

    public static byte[] _c_pri_key = new byte[0];
    public static byte[] _c_pub_key = new byte[0];
    public static PrivateKey pkcs8PrivateKey;
    public static PublicKey x509PublicKey;

    private static PublicKey constructX509PublicKey(String str) {
        try {
            return new EcdhKeyFactorySpi().engineGeneratePublic(new X509EncodedKeySpec(HexUtils.hexStringToBytes(str)));
        } catch (InvalidKeySpecException e) {
        }

        return null;
    }

    private int initShareKeyByBouncycastle() throws Exception {

        // 初始化Bouncy Castle Provider
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGeneratorSpi keyGen = new KeyPairGeneratorSpi.ECDH();

        keyGen.initialize(new ECGenParameterSpec("prime256v1"));
        KeyPair keyPair = keyGen.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        byte[] encoded = publicKey.getEncoded();
        PrivateKey privateKey = keyPair.getPrivate();
        privateKey.getEncoded();

        // 计算共享密钥
        EcdhKeyAgreementSpi keyAgreementSpi = new EcdhKeyAgreementSpi();
        keyAgreementSpi.engineInit(keyPair.getPrivate(), new SecureRandom());
        PublicKey constructX509PublicKey = constructX509PublicKey(X509_SERVER_PUB_KEY);
        keyAgreementSpi.engineDoPhase(constructX509PublicKey, true);
        byte[] data = keyAgreementSpi.engineGenerateSecret();
        byte[] bArr = new byte[16];
        System.arraycopy(data, 0, bArr, 0, 16);
        _g_share_key = MD5.hash(bArr);
        byte[] bArr2 = new byte[65];
        _c_pub_key = bArr2;
        System.arraycopy(encoded, 26, bArr2, 0, 65);

        x509PublicKey = publicKey;
        pkcs8PrivateKey = privateKey;

        return 0;
    }

    public int initShareKey() {
        try {
            return initShareKeyByBouncycastle();
        } catch (Exception e) {
        }

        return 0;
    }

}
