package com.accommodationbooking.authorizationservice.config.converter;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.encrypt.TextEncryptor;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Converter
@RequiredArgsConstructor
public class RsaPublicKeyConverter implements AttributeConverter<RSAPublicKey, String> {
    private final TextEncryptor textEncryptor;

    @Override
    public String convertToDatabaseColumn(RSAPublicKey attribute) {
        var x509EncodedKeySpec = new X509EncodedKeySpec(attribute.getEncoded());
        var pem = "-----BEGIN PUBLIC KEY-----\n" +
                Base64.getMimeEncoder().encodeToString(x509EncodedKeySpec.getEncoded()) +
                "\n-----END PUBLIC KEY-----";
        return this.textEncryptor.encrypt(pem);
    }

    @Override
    public RSAPublicKey convertToEntityAttribute(String dbData) {
        try {
            var pem = textEncryptor.decrypt(dbData);
            var publicKeyPEM = pem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "");
            var encoded = Base64.getMimeDecoder().decode(publicKeyPEM);
            var keyFactory = KeyFactory.getInstance("RSA");
            var keySpec = new X509EncodedKeySpec(encoded);
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (final Throwable throwable) {
            throw new IllegalArgumentException("Cannot deserialize public key", throwable);
        }
    }
}
