package io.security.oauth2.springsecurityoauth2;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.SignatureException;

public class SignatureTest {
    public static void signature(String message) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.genKeyPair();

        //전자 서명
        byte[] data = message.getBytes("UTF-8");
        Signature signature = Signature.getInstance("UTF-8");
        signature.initSign(keyPair.getPrivate());
        signature.update(data);

        byte[] sign = signature.sign();

        // 검증
        signature.initVerify(keyPair.getPublic());
        signature.update(data);

        boolean verified = false;

        try {
            verified = signature.verify(sign);
        }
        catch (SignatureException e) {
            System.out.println("전자서명 실행 중 오류발생");
            e.printStackTrace();
        }
        if(verified)
            System.out.println("전자서명 검증 성공");
        else
            System.out.println("전자서명 검증 실패");

    }
}
