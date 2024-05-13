package com.accommodationbooking.authorizationservice.security.service;

import com.accommodationbooking.authorizationservice.dto.UserLoginRequestDto;
import com.accommodationbooking.authorizationservice.dto.UserLoginResponseDto;
import com.accommodationbooking.authorizationservice.dto.UserRegistrationRequestDto;
import com.accommodationbooking.authorizationservice.dto.UserResponseDto;

import java.util.Map;

public interface AuthenticationService {
    UserResponseDto register(final UserRegistrationRequestDto registrationDto);

    UserLoginResponseDto login(final UserLoginRequestDto loginDto);

    Map<String, Object> getJwks();
}
