package com.example.demo.dto.token;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class TokenDto {
    // 승인 타입
    private String grantType;
    // 액세스 토큰
    private String accessToken;
    // 리프레시 토큰
    private String refreshToken;
    // 액세스 토큰 만료시간
    private long accessTokenExpiresIn;
}
