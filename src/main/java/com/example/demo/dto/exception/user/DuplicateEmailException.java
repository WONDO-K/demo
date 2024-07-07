package com.example.demo.dto.exception.user;

import com.example.demo.dto.exception.CustomException;
import com.example.demo.dto.exception.ErrorCode;

public class DuplicateEmailException extends CustomException {
    public DuplicateEmailException() {
        super(ErrorCode.DUPLICATE_EMAIL);
    }
}
