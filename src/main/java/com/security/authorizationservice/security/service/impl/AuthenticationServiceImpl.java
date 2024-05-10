package com.security.authorizationservice.security.service.impl;

import com.nimbusds.jose.jwk.JWKSet;
import com.security.authorizationservice.dto.UserLoginRequestDto;
import com.security.authorizationservice.dto.UserLoginResponseDto;
import com.security.authorizationservice.dto.UserRegistrationRequestDto;
import com.security.authorizationservice.dto.UserResponseDto;
import com.security.authorizationservice.error.RegistrationException;
import com.security.authorizationservice.mapper.UserMapper;
import com.security.authorizationservice.model.User;
import com.security.authorizationservice.repository.UserRepository;
import com.security.authorizationservice.security.service.AuthenticationService;
import com.security.authorizationservice.security.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {
    private final UserRepository userRepository;
    private final UserMapper userMapper;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;
    private final JWKSet jwkSet;

    @Override
    public UserResponseDto register(final UserRegistrationRequestDto registrationDto) {
        validateUserRegistration(registrationDto);

        final User userToSave = userMapper.toModel(registrationDto);
        userToSave.setPassword(passwordEncoder.encode(registrationDto.password()));
        final User savedUser = userRepository.save(userToSave);
        return userMapper.toDto(savedUser);
    }

    @Override
    public UserLoginResponseDto login(final UserLoginRequestDto loginDto) {
        final var authToken = new UsernamePasswordAuthenticationToken(
                loginDto.email(),
                loginDto.password()
        );
        final Authentication authentication = authenticationManager.authenticate(authToken);
        final String jwt = jwtService.generateToken(authentication);
        return new UserLoginResponseDto(jwt);
    }

    @Override
    public Map<String, Object> getJwks() {
        return jwkSet.toJSONObject(true);
    }

    private void validateUserRegistration(final UserRegistrationRequestDto registrationDto) {
        final String email = registrationDto.email();
        if (userRepository.existsByEmail(email)) {
            throw new RegistrationException("User with email " + email + " already exists");
        }
    }
}
