package com.example.demo.service.impl;

import com.example.demo.domain.User;
import com.example.demo.dto.exception.user.UserNotFoundException;
import com.example.demo.dto.token.TokenDto;
import com.example.demo.dto.user.LoginRequestDto;
import com.example.demo.dto.user.SignUpRequestDto;
import com.example.demo.enums.Role;
import com.example.demo.jwt.TokenProvider;
import com.example.demo.repository.UserRepository;
import com.example.demo.service.UserService;
import com.example.demo.util.SecurityUtil;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Transactional
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final TokenProvider tokenProvider;

    private final Logger log = LoggerFactory.getLogger(getClass());

    @Override
    public void signup(SignUpRequestDto dto){
        // User 클래스 틀에 맞춰 값 대입
        User user = User.builder()
                .username(dto.getId())
                .pw(passwordEncoder.encode(dto.getPw()))
                .email(dto.getEmail())
                .nickname(dto.getNickname())
                .role(Role.USER)
                .phone(dto.getPhone())
                .build();
        // 문제 없으면 저장
        try {
            userRepository.save(user);
            log.info("회원가입이 완료되었습니다.");
            // 문제 생기면 오류 발생
        } catch (DataIntegrityViolationException e){
            // DataIntegrityViolationException : 뭔가 잘못된 데이터가 바인딩 되었을때 발생하는 에러이다. SQL 문이 잘못되었거나 Data가 잘못되었을 경우
            String errorMessage = "바인딩 오류: " + e.getMessage();
            log.error(errorMessage);
            e.printStackTrace();
        }

    }

    @Override
    @Transactional(readOnly = true)
    public boolean checkId(String username) {
        // user id로 검색 후 존재유무를 bool값으로 전달
        Optional<User> entity = userRepository.findByUsername(username);
        return entity.isPresent();
    }

    @Override
    @Transactional(readOnly = true)
    public boolean checkNickname(String nickname){
        // nickname으로 검색후 존재 유무를 bool값으로 전달
        Optional<User> entity = userRepository.findByNickname(nickname);
        return entity.isPresent();
    }

    @Override
    @Transactional(readOnly = true)
    public boolean checkEmail(String email){
        // email로 검색후 존재 유무를 bool값으로 전달
        Optional<User> entity = userRepository.findByEmail(email);
        return entity.isPresent();
    }

    @Override
    public TokenDto doLogin(LoginRequestDto loginDto) {
        // 아이디와 비밀번호로 AuthenticationToken 생성
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPw());
        log.info("authenticationToken : " + authenticationToken);

        // CustomUserDetailsService의 loadByUserName실행
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        log.info("authentication : " + authentication);

        // 인증 정보 기반으로 JWT 토큰 생성
        TokenDto tokenDto = tokenProvider.generateTokenDto(authentication);
        System.out.println("tokenDto : "+ tokenDto);

        // RefreshToken 저장
        Optional<User> entity = userRepository.findByUsername(authentication.getName());
        if (entity.isPresent()) {
            entity.get().saveToken(tokenDto.getRefreshToken());
            userRepository.save(entity.get());
        }

        return tokenDto;
    }

    @Override
    @Transactional(readOnly = true)
    public User getMyInfo(){
        return SecurityUtil.getCurrentUsername().flatMap(userRepository::findByUsername)
                .orElseThrow(UserNotFoundException::new);
    }
}
