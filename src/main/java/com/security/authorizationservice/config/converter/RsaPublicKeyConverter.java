package com.security.authorizationservice.config.converter;

import lombok.RequiredArgsConstructor;
import org.springframework.core.serializer.Deserializer;
import org.springframework.core.serializer.Serializer;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.stereotype.Component;
import org.springframework.util.FileCopyUtils;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Component
@RequiredArgsConstructor
public class RsaPublicKeyConverter implements Serializer<RSAPublicKey>, Deserializer<RSAPublicKey> {
    private final TextEncryptor textEncryptor;

    @Override
    public RSAPublicKey deserialize(final InputStream inputStream) {
        try {
            var pem = textEncryptor.decrypt(FileCopyUtils.copyToString(new InputStreamReader(inputStream)));
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

    @Override
    public void serialize(final RSAPublicKey object, final OutputStream outputStream) throws IOException {
        var x509EncodedKeySpec = new X509EncodedKeySpec(object.getEncoded());
        var pem = "-----BEGIN PUBLIC KEY-----\n" +
                Base64.getMimeEncoder().encodeToString(x509EncodedKeySpec.getEncoded()) +
                "\n-----END PUBLIC KEY-----";
        outputStream.write(this.textEncryptor.encrypt(pem).getBytes());
    }
}
