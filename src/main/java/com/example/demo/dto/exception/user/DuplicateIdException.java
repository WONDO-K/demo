package com.example.demo.dto.exception.user;

import com.example.demo.dto.exception.CustomException;
import com.example.demo.dto.exception.ErrorCode;

public class DuplicateIdException extends CustomException {

    public DuplicateIdException() {
        super(ErrorCode.DUPLICATE_ID);
    }
}
