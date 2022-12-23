package io.security.oauth2.springsecurityoauth2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.MessageDigest;

@SpringBootApplication
public class SpringSecurityOauth2Application {
    public static void main(String[] args) throws Exception {
//        MessageDigestTest.messageDigest("hi");
        SignatureTest.signature("hi");
//        SpringApplication.run(SpringSecurityOauth2Application.class, args);
    }
}
