package com.example.demo.service;

import com.example.demo.domain.User;
import com.example.demo.dto.token.TokenDto;
import com.example.demo.dto.user.LoginRequestDto;
import com.example.demo.dto.user.SignUpRequestDto;
import org.springframework.stereotype.Service;

@Service
public interface UserService {

    public void signup(SignUpRequestDto dto);

    boolean checkId(String userid);

    boolean checkNickname(String nickname);

    boolean checkEmail(String email);

    TokenDto doLogin(LoginRequestDto requestDto);

    User getMyInfo();
}
