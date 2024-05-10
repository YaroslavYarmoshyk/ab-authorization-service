package com.security.authorizationservice.error;

import com.fasterxml.jackson.annotation.JsonFormat;
import org.springframework.http.HttpStatus;

import java.time.ZonedDateTime;
import java.util.Collection;

import static com.security.authorizationservice.constants.DateTimeConstants.ERROR_DATE_FORMAT_PATTERN;

public record ApiError(
        @JsonFormat(pattern = ERROR_DATE_FORMAT_PATTERN)
        ZonedDateTime timestamp,
        HttpStatus status,
        int code,
        Collection<String> errors
) {
}
