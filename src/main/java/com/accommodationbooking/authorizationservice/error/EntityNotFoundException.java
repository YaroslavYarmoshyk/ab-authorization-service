package com.accommodationbooking.authorizationservice.error;

import lombok.Getter;

@Getter
public class EntityNotFoundException extends RuntimeException {
    private final String message;

    public EntityNotFoundException(final String message) {
        super(message);
        this.message = message;
    }
}
