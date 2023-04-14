# Java实现ECDH算法示例程序

ECDH（Elliptic Curve Diffie-Hellman）算法是基于椭圆曲线密码学的密钥交换协议，用于协商双方之间的共享秘钥。Java提供了丰富的加密库，可以方便地实现ECDH算法。以下介绍一种纯Java实现的ECDH算法示例程序，该程序可以运行在Android上。

### 实现方法

我们可以通过使用Java的加密库，实现ECDH算法。以下是ECDH算法的实现方法：

1. 确定椭圆曲线参数a, b, p, G, n，其中a, b, p分别表示椭圆曲线的参数，G为基点，n为阶数；
2. 一方选择一个私钥d，计算公钥Q = dG；
3. 另一方也选择一个私钥e，计算公钥P = eG ；
4. 将公钥P发送给第一方，第一方使用私钥d计算出协商密钥S = dP；
5. 将公钥Q发送给第二方，第二方使用私钥e计算出协商密钥T = eQ；
6. 对于任意一对ECDH协商，S = T，S即为最终协商密钥。

以下是代码示例：

```java
package com.doumsg;

import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class EcdhCrypt {

    public static final String X509_SERVER_PUB_KEY = "3046301006072A8648CE3D020106052B8104001F03320004B431A6E5CBB02351DC542A505F4497FF64761A85F358B7B12F3FC884807686917786ECE2C2B7188CA2D57B64286D54C1\n";
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

```

### 在Android上实现

可以通过使用Android提供的Java加密库，实现ECDH算法。具体实现方法，可以参考上面的示例程序。需要注意，Android的加密库可能与Java标准库略有不同，因此需要根据具体库进行使用和调试。

## 总结

ECDH算法是一种安全、高效的密钥交换协议，可以用Java实现。在实际应用中，应该注意选择安全的椭圆曲线参数，以确保数据的安全。