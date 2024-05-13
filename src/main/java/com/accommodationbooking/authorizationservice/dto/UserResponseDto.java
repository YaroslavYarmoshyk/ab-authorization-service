package com.accommodationbooking.authorizationservice.dto;

public record UserResponseDto(
        Long id,
        String email,
        String firstName,
        String lastName
) {
}
