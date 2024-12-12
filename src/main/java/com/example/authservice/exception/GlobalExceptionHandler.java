package com.example.authservice.exception;

import com.example.authservice.model.dto.ErrorResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(value = EmailAlreadyExistsException.class)
    ResponseEntity<ErrorResponse> handlingEmailAlreadyExistsException(RuntimeException exception) {
        log.error("Exception: ", exception);
        ErrorResponse response = new ErrorResponse(exception.getMessage());

        return new ResponseEntity<>(response, HttpStatus.NOT_ACCEPTABLE);
    }

    @ExceptionHandler(value = UsernameAlreadyExistException.class)
    ResponseEntity<ErrorResponse> handlingUsernameAlreadyExistException(RuntimeException exception) {
        log.error("Exception: ", exception);
        ErrorResponse response = new ErrorResponse(exception.getMessage());

        return new ResponseEntity<>(response, HttpStatus.NOT_ACCEPTABLE);
    }

    @ExceptionHandler(value = RuntimeException.class)
    ResponseEntity<ErrorResponse> handlingRuntimeException(RuntimeException exception) {
        log.error("Exception: ", exception);
        ErrorResponse response = new ErrorResponse(exception.getMessage());

        return new ResponseEntity<>(response,HttpStatus.INTERNAL_SERVER_ERROR);
    }

}
