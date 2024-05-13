package com.accommodationbooking.authorizationservice.error;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class SystemException extends RuntimeException {
    private final String message;
    private final HttpStatus status;

    public SystemException(final String message, HttpStatus status) {
        super(message);
        this.message = message;
        this.status = status;
    }
}
