package io.security.oauth2.springsecurityoauth2;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSATest {

    public static void rsa(String message) throws Exception {

        KeyPair keyPair = RSAGen.genKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        String encrypted = RSAGen.encrypt(message, publicKey);
        String decrypted = RSAGen.decrypt(encrypted, privateKey);

        System.out.println("message = " + message);
        System.out.println("decrypted = " + decrypted);

        // key spec 전환하기
        byte[] bytePublicKey = publicKey.getEncoded();
        String base64PublicKey = Base64.getEncoder().encodeToString(bytePublicKey);
        byte[] bytePrivateKey = privateKey.getEncoded();
        String base64PrivateKey = Base64.getEncoder().encodeToString(bytePrivateKey);

        // X.509 표준형식
        PublicKey X509PublicKey = RSAGen.getPublicKeyFromKeySpec(base64PublicKey);
        String encrypted2 = RSAGen.encrypt(message, X509PublicKey);
        String decrypted2 = RSAGen.decrypt(encrypted2, privateKey);

        System.out.println("message = " + message);
        System.out.println("decrypted2 = " + decrypted2);

        // PKCS8 표준형식
        PrivateKey PKCS8PrivateKey = RSAGen.getPrivateKeyFromKeySpec(base64PrivateKey);
        String decrypted3 = RSAGen.decrypt(encrypted2, PKCS8PrivateKey);

        System.out.println("message = " + message);
        System.out.println("decrypted3 = " + decrypted3);
    }
}
