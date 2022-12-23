package io.security.oauth2.springsecurityoauth2;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class MacTest {
    public static void hmac(String data) throws Exception {
        hamcBase64("secretKey", data, "HmacMD5");
        hamcBase64("secretKey",data,"HmacSHA256");

    }

    private static void hamcBase64(String secret, String data, String algorithms) throws Exception{
        SecretKeySpec secretKey = new SecretKeySpec(secret.getBytes("utf-8"), algorithms);
        Mac mac = Mac.getInstance(algorithms);
        mac.init(secretKey);
        byte[] hash = mac.doFinal(data.getBytes());
        String encodedStr = Base64.getEncoder().encodeToString(hash);
        System.out.println(algorithms + ": " + encodedStr);
    }
}
