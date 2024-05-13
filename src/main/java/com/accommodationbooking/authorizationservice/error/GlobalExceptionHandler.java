package com.accommodationbooking.authorizationservice.error;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.time.ZonedDateTime;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

@ControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(
            final MethodArgumentNotValidException ex,
            final HttpHeaders headers,
            final HttpStatusCode status,
            final WebRequest request
    ) {
        final List<String> errors = ex.getBindingResult().getAllErrors().stream()
                .map(this::getErrorMessage)
                .toList();
        final ApiError apiError = getApiError(HttpStatus.BAD_REQUEST, errors);
        return new ResponseEntity<>(apiError, headers, status);
    }

    @ExceptionHandler(value = SystemException.class)
    protected ResponseEntity<ApiError> handleSystemException(final SystemException ex) {
        final ApiError apiError = getApiError(ex.getStatus(), ex.getMessage());
        return new ResponseEntity<>(apiError, HttpStatusCode.valueOf(apiError.code()));
    }

    @ExceptionHandler(value = EntityNotFoundException.class)
    protected ResponseEntity<ApiError> handleEntityNotFound(final EntityNotFoundException ex) {
        final ApiError apiError = getApiError(HttpStatus.NOT_FOUND, ex.getMessage());
        return new ResponseEntity<>(apiError, HttpStatusCode.valueOf(apiError.code()));
    }

    @ExceptionHandler(value = BadCredentialsException.class)
    protected ResponseEntity<ApiError> handleBadCredentialsException(final BadCredentialsException ex) {
        final ApiError apiError = getApiError(HttpStatus.BAD_REQUEST, ex.getMessage());
        return new ResponseEntity<>(apiError, HttpStatusCode.valueOf(apiError.code()));
    }

    @ExceptionHandler(value = RegistrationException.class)
    protected ResponseEntity<ApiError> handleRegistrationException(final RegistrationException ex) {
        final ApiError apiError = getApiError(HttpStatus.BAD_REQUEST, ex.getMessage());
        return new ResponseEntity<>(apiError, HttpStatusCode.valueOf(apiError.code()));
    }

    private static ApiError getApiError(final HttpStatus status, final String error) {
        return getApiError(status, Collections.singleton(error));
    }

    private static ApiError getApiError(final HttpStatus status, final Collection<String> errors) {
        return new ApiError(ZonedDateTime.now(), status, status.value(), errors);
    }

    private String getErrorMessage(ObjectError e) {
        if (e instanceof FieldError fieldError) {
            String field = fieldError.getField();
            String message = e.getDefaultMessage();
            return field + " " + message;
        }
        return e.getDefaultMessage();
    }
}
