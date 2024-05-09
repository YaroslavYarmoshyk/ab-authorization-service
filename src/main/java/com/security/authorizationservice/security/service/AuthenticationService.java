package com.security.authorizationservice.security.service;

import com.security.authorizationservice.dto.UserLoginRequestDto;
import com.security.authorizationservice.dto.UserLoginResponseDto;
import com.security.authorizationservice.dto.UserRegistrationRequestDto;
import com.security.authorizationservice.dto.UserResponseDto;

public interface AuthenticationService {
    UserResponseDto register(final UserRegistrationRequestDto registrationDto);

    UserLoginResponseDto login(final UserLoginRequestDto loginDto);
}
