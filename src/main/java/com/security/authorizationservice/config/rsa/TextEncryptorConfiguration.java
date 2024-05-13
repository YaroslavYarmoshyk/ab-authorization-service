package com.security.authorizationservice.config.rsa;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;

@Configuration
public class TextEncryptorConfiguration {
    @Bean
    public TextEncryptor textEncryptor(@Value("${jwt.persistence.password}") String pw,
                                       @Value("${jwt.persistence.salt}") String salt) {
        return Encryptors.text(pw, salt);
    }
}
