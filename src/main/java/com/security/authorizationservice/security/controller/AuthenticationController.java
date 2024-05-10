package com.security.authorizationservice.security.controller;

import com.security.authorizationservice.dto.UserLoginRequestDto;
import com.security.authorizationservice.dto.UserLoginResponseDto;
import com.security.authorizationservice.dto.UserRegistrationRequestDto;
import com.security.authorizationservice.dto.UserResponseDto;
import com.security.authorizationservice.security.service.AuthenticationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@Tag(name = "Authentication management", description = "Endpoint for registration and login")
@RestController
@RequestMapping(value = "/api/auth")
@RequiredArgsConstructor
public class AuthenticationController {
        private final AuthenticationService authenticationService;

    @PostMapping(value = "/register")
    @Operation(summary = "Register a new user", description = "Register a new user")
    public UserResponseDto register(@Valid @RequestBody UserRegistrationRequestDto requestDto) {
        return authenticationService.register(requestDto);
    }

    @PostMapping(value = "/login")
    @Operation(summary = "Login a user", description = "Login a user")
    public UserLoginResponseDto login(@Valid @RequestBody UserLoginRequestDto requestDto) {
        return authenticationService.login(requestDto);
    }

    @GetMapping("/oauth2/jwks")
    @Operation(summary = "Get jwks", description = "Get jwks configurations")
    public Map<String, Object> getJwks() {
        return authenticationService.getJwks();
    }
}
