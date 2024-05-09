package com.security.authorizationservice.mapper;


import com.security.authorizationservice.config.mapper.MapperConfig;
import com.security.authorizationservice.dto.UserRegistrationRequestDto;
import com.security.authorizationservice.dto.UserResponseDto;
import com.security.authorizationservice.model.User;
import org.mapstruct.Mapper;

@Mapper(config = MapperConfig.class)
public interface UserMapper {
    UserResponseDto toDto(final User user);

    User toModel(final UserRegistrationRequestDto registrationDto);
}
