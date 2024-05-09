package com.security.authorizationservice.config.converter;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.encrypt.TextEncryptor;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

@Converter
@RequiredArgsConstructor
public class RsaPrivateKeyConverter implements AttributeConverter<RSAPrivateKey, String> {
    private final TextEncryptor textEncryptor;

    @Override
    public String convertToDatabaseColumn(RSAPrivateKey attribute) {
        var pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(attribute.getEncoded());
        var string = "-----BEGIN PRIVATE KEY-----\n" + Base64.getMimeEncoder().encodeToString(pkcs8EncodedKeySpec.getEncoded())
                + "\n-----END PRIVATE KEY-----";
        return this.textEncryptor.encrypt(string);
    }

    @Override
    public RSAPrivateKey convertToEntityAttribute(String dbData) {
        try {
            var pem = this.textEncryptor.decrypt(dbData);
            var privateKeyPEM = pem
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "");
            var encoded = Base64.getMimeDecoder().decode(privateKeyPEM);
            var keyFactory = KeyFactory.getInstance("RSA");
            var keySpec = new PKCS8EncodedKeySpec(encoded);
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (final Throwable throwable) {
            throw new IllegalArgumentException("Cannot deserialize private key", throwable);
        }
    }
}
