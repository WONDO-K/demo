package com.example.demo.dto.exception.user;

import com.example.demo.dto.exception.CustomException;
import com.example.demo.dto.exception.ErrorCode;

public class DuplicateNicknameException extends CustomException {
    public DuplicateNicknameException(){super(ErrorCode.DUPLICATE_NICKNAME);}
}
