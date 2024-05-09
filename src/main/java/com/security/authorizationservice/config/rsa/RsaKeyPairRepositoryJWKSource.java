package com.security.authorizationservice.config.rsa;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.security.authorizationservice.repository.RsaKeyPairRepository;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Component
public class RsaKeyPairRepositoryJWKSource implements JWKSource<SecurityContext>, OAuth2TokenCustomizer<JwtEncodingContext> {

    private final RsaKeyPairRepository keyPairRepository;

    RsaKeyPairRepositoryJWKSource(RsaKeyPairRepository keyPairRepository) {
        this.keyPairRepository = keyPairRepository;
    }

    @Override
    public List<JWK> get(final JWKSelector jwkSelector,
                         final SecurityContext context) {
        var keyPairs = this.keyPairRepository.findAll();
        return keyPairs.stream()
                .map(keyPair -> new RSAKey.Builder(keyPair.getPublicKey())
                        .privateKey(keyPair.getPrivateKey())
                        .keyID(keyPair.getId())
                        .build())
                .filter(jwkSelector.getMatcher()::matches)
                .collect(Collectors.toList());
    }

    @Override
    public void customize(final JwtEncodingContext context) {
        var keyPairs = this.keyPairRepository.findAll();
        var kid = keyPairs.getFirst().getId();
        context.getJwsHeader().keyId(kid);
    }
}
