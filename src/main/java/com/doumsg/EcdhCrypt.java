package com.doumsg;

import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class EcdhCrypt {

    public static final String X509_SERVER_PUB_KEY = "3046301006072A8648CE3D020106052B8104001F03320004928D8850673088B343264E0C6BACB8496D697799F37211DEB25BB73906CB089FEA9639B4E0260498B51A992D50813DA8";
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

        keyGen.initialize(new ECGenParameterSpec("secp192k1"));
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
        _g_share_key = MD5.hash(data);

        _c_pub_key = new byte[49];
        System.arraycopy(encoded, 23, _c_pub_key, 0, 49);

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
