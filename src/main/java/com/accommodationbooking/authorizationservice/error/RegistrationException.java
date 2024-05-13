package com.accommodationbooking.authorizationservice.error;

import lombok.Getter;

@Getter
public class RegistrationException extends RuntimeException {
    private final String message;

    public RegistrationException(final String message) {
        super(message);
        this.message = message;
    }
}
