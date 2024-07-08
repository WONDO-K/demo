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

    // 로그 처리
    private final Logger log = LoggerFactory.getLogger(getClass());

    /**
     * 회원 가입 처리 메서드
     *
     * @param dto 회원 가입 요청 DTO
     */
    @Override
    public void signup(SignUpRequestDto dto) {
        // User 객체 생성 및 값 설정
        User user = User.builder()
                .username(dto.getId())
                .pw(passwordEncoder.encode(dto.getPw()))
                .email(dto.getEmail())
                .nickname(dto.getNickname())
                .role(Role.USER)
                .phone(dto.getPhone())
                .build();
        try {
            userRepository.save(user); // 회원 정보 저장
            log.info("회원가입이 완료되었습니다."); // 성공 로그 출력
        } catch (DataIntegrityViolationException e) {
            // 데이터 바인딩 예외 발생 시 처리
            String errorMessage = "바인딩 오류: " + e.getMessage();
            log.error(errorMessage); // 오류 로그 출력
            e.printStackTrace(); // 예외 추적 정보 출력
        }
    }

    /**
     * 아이디 중복 체크 메서드
     *
     * @param username 체크할 사용자 아이디
     * @return 아이디의 존재 여부 (true: 존재함, false: 존재하지 않음)
     */
    @Override
    @Transactional(readOnly = true)
    public boolean checkId(String username) {
        Optional<User> entity = userRepository.findByUsername(username);
        return entity.isPresent(); // 사용자 아이디 존재 여부 반환
    }

    /**
     * 닉네임 중복 체크 메서드
     *
     * @param nickname 체크할 사용자 닉네임
     * @return 닉네임의 존재 여부 (true: 존재함, false: 존재하지 않음)
     */
    @Override
    @Transactional(readOnly = true)
    public boolean checkNickname(String nickname) {
        Optional<User> entity = userRepository.findByNickname(nickname);
        return entity.isPresent(); // 사용자 닉네임 존재 여부 반환
    }

    /**
     * 이메일 중복 체크 메서드
     *
     * @param email 체크할 사용자 이메일
     * @return 이메일의 존재 여부 (true: 존재함, false: 존재하지 않음)
     */
    @Override
    @Transactional(readOnly = true)
    public boolean checkEmail(String email) {
        Optional<User> entity = userRepository.findByEmail(email);
        return entity.isPresent(); // 사용자 이메일 존재 여부 반환
    }

    /**
     * 사용자 로그인 처리 메서드
     *
     * @param loginDto 로그인 요청 DTO
     * @return 생성된 JWT 토큰 정보
     */
    @Override
    public TokenDto doLogin(LoginRequestDto loginDto) {
        // 아이디와 비밀번호를 기반으로 AuthenticationToken 생성
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPw());
        log.info("authenticationToken : " + authenticationToken);

        // CustomUserDetailsService를 사용하여 Authentication 인증 처리
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication); // SecurityContext에 인증 정보 설정
        log.info("authentication : " + authentication);

        // 인증 정보를 기반으로 JWT 토큰 생성
        TokenDto tokenDto = tokenProvider.generateTokenDto(authentication);
        log.info("tokenDto : " + tokenDto);

        // RefreshToken 저장
        Optional<User> entity = userRepository.findByUsername(authentication.getName());
        if (entity.isPresent()) {
            entity.get().saveToken(tokenDto.getRefreshToken()); // 사용자 엔티티에 RefreshToken 저장
            userRepository.save(entity.get()); // 저장된 엔티티 정보 업데이트
        }

        return tokenDto; // 생성된 JWT 토큰 반환
    }

    /**
     * 내 정보 조회 메서드
     *
     * @return 현재 인증된 사용자의 정보
     * @throws UserNotFoundException 사용자를 찾을 수 없는 경우 예외 발생
     */
    @Override
    @Transactional(readOnly = true)
    public User getMyInfo() {
        // SecurityUtil을 사용하여 현재 인증된 사용자의 이름을 가져온 후 UserRepository를 통해 사용자 정보 조회
        return SecurityUtil.getCurrentUsername()
                .flatMap(userRepository::findByUsername)
                .orElseThrow(UserNotFoundException::new); // 사용자를 찾을 수 없으면 예외 발생
    }
}
