package com.accommodationbooking.authorizationservice.security.service;

import org.springframework.security.core.Authentication;

public interface JwtService {
    String generateToken(final Authentication authentication);
}
