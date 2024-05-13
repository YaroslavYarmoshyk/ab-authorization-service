package com.accommodationbooking.authorizationservice.mapper;


import com.accommodationbooking.authorizationservice.config.mapper.MapperConfig;
import com.accommodationbooking.authorizationservice.dto.UserRegistrationRequestDto;
import com.accommodationbooking.authorizationservice.dto.UserResponseDto;
import com.accommodationbooking.authorizationservice.model.User;
import org.mapstruct.Mapper;

@Mapper(config = MapperConfig.class)
public interface UserMapper {
    UserResponseDto toDto(final User user);

    User toModel(final UserRegistrationRequestDto registrationDto);
}
