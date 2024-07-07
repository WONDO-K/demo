package com.example.demo.config;

import lombok.AllArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.FrameOptionsConfig;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@AllArgsConstructor
@EnableMethodSecurity
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(CsrfConfigurer<HttpSecurity>::disable)
                .headers(headers -> headers.frameOptions(FrameOptionsConfig::sameOrigin))    // H2 콘솔 사용을 위한 설정
                .authorizeHttpRequests(requests ->
                        requests.requestMatchers(
                                        "/api/v1/**/auth/**", // API v1 버전의 인증 관련 API는 모두 허용
                                        "/api/v1/**/any/**", // API v1 버전의 일반 API는 모두 허용
                                        "/swagger-resources/**", // 스웨거 리소스에 대한 요청은 모두 허용
                                        "/configuration/ui", // 스웨거 UI 설정에 대한 요청은 모두 허용
                                        "/configuration/security", // 스웨거 보안 설정에 대한 요청은 모두 허용
                                        "/swagger-ui/**", // 스웨거 UI 페이지에 대한 요청은 모두 허용
                                        "/webjars/**", // 웹 자원(JAR 파일)에 대한 요청은 모두 허용
                                        "/v3/api-docs/**" // 스웨거 3.0 이상의 API 문서 엔드포인트는 모두 허용
                                ).permitAll()    // requestMatchers의 인자로 전달된 url은 모두에게 허용
                                .requestMatchers(PathRequest.toH2Console()).permitAll()    // H2 콘솔 접속은 모두에게 허용

                                .anyRequest().authenticated()    // 그 외의 모든 요청은 인증 필요
                )
                .sessionManagement(sessionManagement ->
                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )    // 세션을 사용하지 않으므로 STATELESS 설정
                .build();
    }
}
