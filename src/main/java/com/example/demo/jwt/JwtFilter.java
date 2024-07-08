package com.example.demo.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

/**
 * JWT 토큰을 검증하고 인증 정보를 설정하는 필터 클래스.
 * Spring Security의 GenericFilterBean을 상속받아 필터링 로직 구현.
 */
public class JwtFilter extends GenericFilterBean {

    // 로그 처리
    private final Logger log = LoggerFactory.getLogger(getClass());
    
    // HTTP 요청 헤더에서 JWT 토큰을 가져오기 위한 헤더 이름
    private static final String AUTHORIZATION_HEADER = "Authorization";
    // JWT 토큰의 시작을 나타내는 Bearer scheme prefix
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final TokenProvider tokenProvider;

    /**
     * JwtFilter 생성자.
     * @param tokenProvider JWT 토큰을 생성하고 검증하는 TokenProvider 객체.
     */
    public JwtFilter(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    /**
     * HTTP 요청을 필터링하여 JWT 토큰을 검증하고 인증 정보를 설정.
     * @param request ServletRequest 객체
     * @param response ServletResponse 객체
     * @param chain FilterChain 객체
     * @throws IOException 입출력 예외가 발생할 경우
     * @throws ServletException 서블릿 예외가 발생할 경우
     */
    @Override
    public void doFilter(ServletRequest request,
                         ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {

        // HttpServletRequest로 캐스팅하여 HTTP 요청 객체로 변환.
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        // HTTP 요청 헤더에서 JWT 토큰을 추출.
        String jwt = resolveToken(httpServletRequest);
        // HTTP 요청 URI를 가져옴.
        String requestURI = httpServletRequest.getRequestURI();

        // 추출한 JWT 토큰이 존재하고 유효성 검사를 통과한 경우
        if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
            // JWT 토큰을 이용하여 Authentication 객체를 가져옴.
            Authentication authentication = tokenProvider.getAuthentication(jwt);
            // SecurityContext에 Authentication 객체를 설정.
            SecurityContextHolder.getContext().setAuthentication(authentication);
            // 인증 정보 설정 로그를 출력.
            //System.out.println("Security Context에 " + authentication.getName() + " 인증 정보를 저장했습니다. uri : " + requestURI);
            log.info("Security Context에 {} 인증 정보를 저장했습니다. uri : {}", authentication.getName(), requestURI);
        } else {
            // 유효한 JWT 토큰이 없는 경우에 대한 로그를 출력.
            //System.out.println("유효한 JWT 토큰이 없습니다. uri : " + requestURI);
            log.info("유효한 JWT 토큰이 없습니다. uri : {}", requestURI);
        }

        // 다음 필터로 요청을 전달합니다.
        chain.doFilter(request, response);
    }

    /**
     * HTTP 요청 헤더에서 JWT 토큰을 추출.
     * @param request HTTP 요청 객체
     * @return 추출된 JWT 토큰 문자열
     */
    private String resolveToken(HttpServletRequest request) {
        // HTTP 요청의 Authorization 헤더에서 Bearer scheme으로 시작하는 JWT 토큰을 추출.
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        // 추출한 토큰이 존재하고 Bearer scheme으로 시작하는 경우
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
            // Bearer scheme 부분을 제외한 실제 토큰 값을 반환.
            return bearerToken.substring(BEARER_PREFIX.length());
        }
        // 토큰이 존재하지 않거나 유효하지 않은 경우 null을 반환.
        return null;
    }
}
