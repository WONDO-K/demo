package com.example.demo.controller;

import com.example.demo.dto.exception.common.InvalidParameterException;
import com.example.demo.dto.exception.user.DuplicateIdException;
import com.example.demo.dto.token.TokenDto;
import com.example.demo.dto.user.LoginRequestDto;
import com.example.demo.dto.user.SignUpRequestDto;
import com.example.demo.service.UserService;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;

import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/user")
public class UserController {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private final UserService userService;

    @PostMapping("/any/signup")
    @Schema(description = "회원 가입", example = "회원정보를 통해 회원 가입처리")
    public ResponseEntity<String> signup(@Valid @RequestBody SignUpRequestDto requestDto, BindingResult result){
        if (result.hasErrors()){
            throw new InvalidParameterException(result);
        }
        else if (userService.checkId(requestDto.getId())){
            log.info("중복된 ID가 이미 존재합니다.");
            throw new DuplicateIdException();
        } else if (userService.checkEmail(requestDto.getEmail())){
            log.info("중복된 Email이 이미 존재합니다.");
            throw new DuplicateIdException();
        } else if (userService.checkNickname(requestDto.getNickname())) {
            log.info("중복된 닉네임이 이미 존재합니다.");
            throw new DuplicateIdException();
        }
        userService.signup(requestDto);
        return new ResponseEntity<>("SUCCESS", HttpStatus.OK);
    }

    @PostMapping("/any/login")
    @Schema(description = "아이디와 비밀번호를 통해 로그인한다.")
    public ResponseEntity<TokenDto> doLogin(@Valid @RequestBody LoginRequestDto requestDto, BindingResult result){
        if (result.hasErrors()){
            throw new InvalidParameterException(result);
        }
        TokenDto tokenDto = userService.doLogin(requestDto);
        HttpHeaders headers = new HttpHeaders();
        headers.add("Auth", tokenDto.getAccessToken());
        headers.add("Refresh", tokenDto.getRefreshToken());

        return new ResponseEntity<>(tokenDto, headers, HttpStatus.OK);
    }
}
