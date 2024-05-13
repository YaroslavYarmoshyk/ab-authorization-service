package com.accommodationbooking.authorizationservice.config.rsa;

import com.accommodationbooking.authorizationservice.model.RsaKeyPair;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;

@Component
public class RsaKeysGenerator {

    public RsaKeyPair generateKeyPair(final String keyId,
                                      final Instant created) {
        var keyPair = generateRsaKey();
        var publicKey = (RSAPublicKey) keyPair.getPublic();
        var privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return RsaKeyPair.builder()
                .id(keyId)
                .created(created)
                .publicKey(publicKey)
                .privateKey(privateKey)
                .build();
    }

    private static KeyPair generateRsaKey() {
        try {
            var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        }
        catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }
}
