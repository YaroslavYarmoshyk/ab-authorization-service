package com.accommodationbooking.authorizationservice.security.service.impl;

import com.accommodationbooking.authorizationservice.error.EntityNotFoundException;
import com.accommodationbooking.authorizationservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class ApplicationUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {
        return userRepository.findByEmail(username)
                .orElseThrow(() -> new EntityNotFoundException(
                        "User was not found by email: " + username)
                );
    }
}
