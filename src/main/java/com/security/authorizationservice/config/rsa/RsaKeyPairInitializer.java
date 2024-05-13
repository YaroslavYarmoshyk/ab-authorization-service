package com.security.authorizationservice.config.rsa;

import com.security.authorizationservice.model.RsaKeyPair;
import com.security.authorizationservice.repository.RsaKeyPairRepository;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
public class RsaKeyPairInitializer {
    private final RsaKeyPairRepository keyPairRepository;
    private final RsaKeysGenerator rsaKeysGenerator;
    private final String keyId;
    @Getter
    private final RsaKeyPair rsaKeyPair;

    public RsaKeyPairInitializer(final RsaKeyPairRepository keyPairRepository,
                                 final RsaKeysGenerator rsaKeysGenerator,
                                 final @Value("${jwt.key.id}") String keyId) {
        this.keyPairRepository = keyPairRepository;
        this.rsaKeysGenerator = rsaKeysGenerator;
        this.keyId = keyId;
        init();
        this.rsaKeyPair = keyPairRepository.findAll().getFirst();
    }

    private void init() {
        if (keyPairRepository.findAll().isEmpty()) {
            generateNewKeys();
        }
    }

    private void generateNewKeys() {
        keyPairRepository.save(rsaKeysGenerator.generateKeyPair(keyId, Instant.now()));
    }
}
