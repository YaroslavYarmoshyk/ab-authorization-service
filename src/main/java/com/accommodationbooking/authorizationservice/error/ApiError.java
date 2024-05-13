package com.accommodationbooking.authorizationservice.error;

import com.fasterxml.jackson.annotation.JsonFormat;
import org.springframework.http.HttpStatus;

import java.time.ZonedDateTime;
import java.util.Collection;

import static com.accommodationbooking.authorizationservice.constants.DateTimeConstants.ERROR_DATE_FORMAT_PATTERN;

public record ApiError(
        @JsonFormat(pattern = ERROR_DATE_FORMAT_PATTERN)
        ZonedDateTime timestamp,
        HttpStatus status,
        int code,
        Collection<String> errors
) {
}
