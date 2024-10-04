package com.example.authservice.exception;

public class UsernameAlreadyExistException extends RuntimeException{
    public UsernameAlreadyExistException(String msg){
        super(msg);
    }
}
