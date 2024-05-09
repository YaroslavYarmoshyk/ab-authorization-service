package com.security.authorizationservice.config.rsa;

import com.security.authorizationservice.repository.RsaKeyPairRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;

import java.time.Instant;

@Configuration
public class RsaConfiguration {
    @Bean
    public TextEncryptor textEncryptor(@Value("${jwt.persistence.password}") String pw,
                                       @Value("${jwt.persistence.salt}") String salt) {
        return Encryptors.text(pw, salt);
    }

    @Bean
    public ApplicationListener<ApplicationReadyEvent> applicationReadyListener(final ApplicationEventPublisher publisher,
                                                                               final RsaKeyPairRepository rsaKeyPairRepository) {
        return event -> {
            if (rsaKeyPairRepository.findAll().isEmpty())
                publisher.publishEvent(new RsaKeyPairGenerationRequestEvent(Instant.now()));
        };
    }

    @Bean
    public ApplicationListener<RsaKeyPairGenerationRequestEvent> keyPairGenerationRequestListener(
            final RsaKeysGenerator rsaKeysGenerator,
            final RsaKeyPairRepository rsaKeyPairRepository,
            @Value("${jwt.key.id}") String keyId) {
        return event -> rsaKeyPairRepository.save(rsaKeysGenerator.generateKeyPair(keyId, event.getSource()));
    }

}
