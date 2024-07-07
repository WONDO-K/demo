package com.example.demo.dto.exception.user;

import com.example.demo.dto.exception.CustomException;
import com.example.demo.dto.exception.ErrorCode;

public class UserNotFoundException extends CustomException {
    public UserNotFoundException(){
        super(ErrorCode.USER_NOT_FOUND);
    }
}
