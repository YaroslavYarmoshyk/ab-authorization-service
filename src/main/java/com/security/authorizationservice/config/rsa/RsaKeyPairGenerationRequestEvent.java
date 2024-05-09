package com.security.authorizationservice.config.rsa;

import org.springframework.context.ApplicationEvent;

import java.time.Instant;

public class RsaKeyPairGenerationRequestEvent extends ApplicationEvent {

    public RsaKeyPairGenerationRequestEvent(final Instant instant) {
        super(instant);
    }

    @Override
    public Instant getSource() {
        return (Instant) super.getSource();
    }
}
