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
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Component
@RequiredArgsConstructor
public class RsaPrivateKeyConverter implements Serializer<RSAPrivateKey>, Deserializer<RSAPrivateKey> {
    private final TextEncryptor textEncryptor;

    @Override
    public RSAPrivateKey deserialize(final InputStream inputStream) {
        try {
            var pem = this.textEncryptor.decrypt(
                    FileCopyUtils.copyToString(new InputStreamReader(inputStream)));
            var privateKeyPEM = pem
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "");
            var encoded = Base64.getMimeDecoder().decode(privateKeyPEM);
            var keyFactory = KeyFactory.getInstance("RSA");
            var keySpec = new PKCS8EncodedKeySpec(encoded);
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (final Throwable throwable) {
            throw new IllegalArgumentException("Cannot deserialize public key", throwable);
        }
    }

    @Override
    public void serialize(final RSAPrivateKey object, final OutputStream outputStream) throws IOException {
        var pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(object.getEncoded());
        var string = "-----BEGIN PRIVATE KEY-----\n" + Base64.getMimeEncoder().encodeToString(pkcs8EncodedKeySpec.getEncoded())
                + "\n-----END PRIVATE KEY-----";
        outputStream.write(this.textEncryptor.encrypt(string).getBytes());
    }
}
