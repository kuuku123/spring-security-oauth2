package io.security.oauth2.springsecurityoauth2.model.users.impl;

import io.security.oauth2.springsecurityoauth2.model.attributes.Attributes;
import io.security.oauth2.springsecurityoauth2.model.users.OAuth2ProviderUser;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Map;

public class KakaoUser extends OAuth2ProviderUser {

    private final Map<String,Object> subAttributes;

    public KakaoUser(Attributes attributes, OAuth2User oAuth2User, ClientRegistration clientRegistration) {
        super(attributes.getAttributes(), oAuth2User, clientRegistration);
        this.subAttributes = attributes.getSubAttributes();
    }

    @Override
    public String getId() {
        return (String)getAttributes().get("id");
    }

    @Override
    public String getUsername() {
        return (String)subAttributes.get("nickname");
    }

    @Override
    public String getPicture() {
        return (String)subAttributes.get("profile_image_url");
    }
}