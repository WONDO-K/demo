package com.example.demo.jwt;

import com.example.demo.dto.token.TokenDto;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class TokenProvider implements InitializingBean {

    // 로그 처리
    private final Logger log = LoggerFactory.getLogger(getClass());

    private static final String AUTHORITIES_KEY = "auth";
    private static final String BEARER_TYPE = "bearer";
    private static final long ACCESS_TOKEN_EXPIRE_TIME = 1000 * 60 * 60;
    private static final long REFRESH_TOKEN_EXPIRE_TIME = 1000 * 60 * 60 * 24 * 7;

    private final String secret;
    private Key key;

    // 생성자에서 주입받은 secret 값을 사용하여 키 초기화
    public TokenProvider(@Value("${jwt.secret}") String secret){
        this.secret = secret;
    }

    // InitializingBean 인터페이스 구현 메서드
    @Override
    public void afterPropertiesSet(){
        // secret을 BASE64 디코딩하여 바이트 배열로 변환
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        // Key 객체 생성
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    // userId와 authorities를 받아서 TokenDto를 생성하는 메서드
    public TokenDto generateTokenDto(String userId, String authorities){
        long now = (new Date().getTime());

        // Access Token 생성
        Date accessTokenExpiresIn = new Date(now + ACCESS_TOKEN_EXPIRE_TIME);
        String accessToken = Jwts.builder()
                .setSubject(userId) // 토큰을 발급 받는 사람의 아이디 설정
                .claim(AUTHORITIES_KEY, authorities) // 토큰을 발급 받는 사람의 권한 설정
                .setExpiration(accessTokenExpiresIn) // 토큰 만료 시간 설정
                .signWith(key, SignatureAlgorithm.HS512) // 키와 암호화 알고리즘 설정
                .compact();

        // Refresh Token 생성
        String refreshToken = Jwts.builder()
                .setExpiration(new Date(now + REFRESH_TOKEN_EXPIRE_TIME)) // Refresh Token의 만료 시간 설정
                .signWith(key, SignatureAlgorithm.HS512) // 키와 암호화 알고리즘 설정
                .compact();

        // TokenDto 객체 생성 및 반환
        return TokenDto.builder()
                .grantType(BEARER_TYPE)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .accessTokenExpiresIn(accessTokenExpiresIn.getTime())
                .build();
    }

    // Authentication 객체를 받아서 TokenDto를 생성하는 메서드
    public TokenDto generateTokenDto(Authentication authentication){
        // 권한 정보 가져오기
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        // generateTokenDto(String userId, String authorities) 메서드 호출
        return generateTokenDto(authentication.getName(), authorities);
    }

    // 토큰을 받아서 Authentication 객체를 반환하는 메서드
    public Authentication getAuthentication(String token){
        // 토큰 복호화하여 Claims 객체 가져오기
        Claims claims = paresClaims(token);

        // 권한 정보가 없으면 예외 발생
        if (claims.get(AUTHORITIES_KEY) == null){
            throw new RuntimeException("권한 정보가 없는 토큰입니다.");
        }

        // 클레임에서 권한 정보를 가져와서 SimpleGrantedAuthority 객체로 변환 후 Collection 생성
        Collection<? extends GrantedAuthority> authorities =
                // 클레임에서 AUTHORITIES_KEY에 해당하는 권한 정보를 가져옴.
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                        // 각 권한을 SimpleGrantedAuthority 객체로 변환.
                        .map(SimpleGrantedAuthority::new)
                        // 변환된 SimpleGrantedAuthority 객체들을 리스트로 수집하여 Collection을 생성.
                        .collect(Collectors.toList());

        // UserDetails 객체 생성하여 Authentication 객체 반환
        User principal = new User(claims.getSubject(), ",", authorities);
        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    // 토큰의 유효성을 검사하는 메서드
    public boolean validateToken(String token){
        try {
            // 토큰의 서명을 검증하고 유효하면 true 반환
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            log.info("JWT 유효성 검증 성공");
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e){
            log.info("잘못된 JWT 서명입니다.", e);
        } catch (ExpiredJwtException e){
            log.info("만료된 토큰입니다.", e);
        } catch (UnsupportedJwtException e){
            log.info("지원되지 않는 JWT 토큰입니다.", e);
        } catch (IllegalArgumentException e){
            log.info("JWT 토큰이 잘못되었습니다.", e);
        }
        return false;
    }

    // 토큰을 파싱하여 Claims 객체를 반환하는 메서드
    private Claims paresClaims(String token){
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
        } catch (ExpiredJwtException e){
            // 토큰이 만료된 경우, 만료된 Claims 반환
            return e.getClaims();
        }
    }
}
