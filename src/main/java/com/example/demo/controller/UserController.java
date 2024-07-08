package com.example.demo.controller;

import com.example.demo.dto.exception.common.InvalidParameterException;
import com.example.demo.dto.exception.user.DuplicateIdException;
import com.example.demo.dto.token.TokenDto;
import com.example.demo.dto.user.LoginRequestDto;
import com.example.demo.dto.user.SignUpRequestDto;
import com.example.demo.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;

import org.springframework.web.bind.annotation.*;

/**
 * 회원 관련 API를 처리하는 컨트롤러.
 */
@Tag(name = "User", description = "회원 관련 API")
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/user")
public class UserController {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private final UserService userService;

    /**
     * 회원 가입 API
     * @param requestDto 회원 가입 요청 DTO
     * @param result 요청 데이터의 검증 결과
     * @return HttpStatus.OK와 함께 성공 메시지 반환
     * @throws InvalidParameterException 요청 데이터가 유효하지 않을 경우 발생
     * @throws DuplicateIdException 이미 존재하는 ID, Email, 닉네임일 경우 발생
     */
    @PostMapping("/any/signup")
    @Operation(summary = "회원 가입", description = "회원 정보를 통해 회원 가입을 처리.")
    public ResponseEntity<String> signup(@Valid @RequestBody SignUpRequestDto requestDto, BindingResult result) {
        // 요청 데이터의 유효성을 검사하고, 유효하지 않으면 InvalidParameterException 예외를 발생.
        // DuplicateIdException : 회원 가입 시 입력한 ID, Email, 또는 닉네임이 이미 데이터베이스에 존재할 경우 발생시키는 예외
        if (result.hasErrors()) {
            throw new InvalidParameterException(result);
        } else if (userService.checkId(requestDto.getId())) {
            // 이미 존재하는 ID인 경우 DuplicateIdException 예외를 발생.
            log.info("중복된 ID가 이미 존재합니다.");
            throw new DuplicateIdException();
        } else if (userService.checkEmail(requestDto.getEmail())) {
            // 이미 존재하는 Email인 경우 DuplicateIdException 예외를 발생.
            log.info("중복된 Email이 이미 존재합니다.");
            throw new DuplicateIdException();
        } else if (userService.checkNickname(requestDto.getNickname())) {
            // 이미 존재하는 닉네임인 경우 DuplicateIdException 예외를 발생.
            log.info("중복된 닉네임이 이미 존재합니다.");
            throw new DuplicateIdException();
        }
        // 모든 검증을 통과하면 UserService를 통해 회원 가입을 처리.
        userService.signup(requestDto);
        // 성공적으로 처리되었음을 나타내는 HttpStatus.OK와 "SUCCESS" 메시지를 반환.
        return new ResponseEntity<>("SUCCESS", HttpStatus.OK);
    }

    /**
     * 로그인 API
     * @param requestDto 로그인 요청 DTO
     * @param result 요청 데이터의 검증 결과
     * @return HttpStatus.OK와 함께 TokenDto 반환
     * @throws InvalidParameterException 요청 데이터가 유효하지 않을 경우 발생
     */
    @PostMapping("/any/login")
    @Operation(summary = "로그인", description = "아이디와 비밀번호를 이용하여 로그인.")
    public ResponseEntity<TokenDto> doLogin(@Valid @RequestBody LoginRequestDto requestDto, BindingResult result) {
        // 요청 데이터의 유효성을 검사하고, 유효하지 않으면 InvalidParameterException 예외를 발생.
        if (result.hasErrors()) {
            throw new InvalidParameterException(result);
        }
        // UserService를 통해 로그인 처리를 수행하고, 결과로 TokenDto를 받아옴.
        TokenDto tokenDto = userService.doLogin(requestDto);
        // HTTP 응답 헤더에 Access Token과 Refresh Token을 추가.
        HttpHeaders headers = new HttpHeaders();
        headers.add("Auth", tokenDto.getAccessToken());
        headers.add("Refresh", tokenDto.getRefreshToken());

        // TokenDto와 함께 HttpStatus.OK를 반환.
        return new ResponseEntity<>(tokenDto, headers, HttpStatus.OK);
    }
}
