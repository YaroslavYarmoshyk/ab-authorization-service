package com.security.authorizationservice.error;

import com.fasterxml.jackson.annotation.JsonFormat;
import org.springframework.http.HttpStatus;

import java.time.LocalDateTime;
import java.util.Collection;

import static com.security.authorizationservice.constants.DateTimeConstants.ERROR_DATE_FORMAT_PATTERN;

public record ApiError(
        @JsonFormat(pattern = ERROR_DATE_FORMAT_PATTERN)
        LocalDateTime timestamp,
        HttpStatus status,
        int code,
        Collection<String> errors
) {
}
