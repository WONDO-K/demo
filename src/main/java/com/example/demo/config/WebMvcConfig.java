package com.example.demo.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@RequiredArgsConstructor
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    // CORS 설정을 추가합니다.
    @Override
    public void addCorsMappings(CorsRegistry registry){
        registry.addMapping("/**") // 모든 경로에 대해 CORS 설정을 적용합니다.
                .allowedOriginPatterns("*") // 모든 도메인에서의 요청을 허용합니다.
                .allowCredentials(true) // 클라이언트가 자격 증명 정보(cookie, HTTP 인증)를 포함하도록 허용합니다.
                .allowedMethods("*") // 모든 HTTP 메서드(GET, POST 등)를 허용합니다.
                .maxAge(3600); // 요청의 유효 기간을 설정합니다. (초 단위, 3600초 = 1시간)
    }

    // 리소스 핸들러를 추가합니다.
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        // Swagger UI 경로를 예외 처리합니다.
        registry.addResourceHandler("/swagger-ui/**")
                .addResourceLocations("classpath:/META-INF/resources/webjars/springdoc-openapi-ui/")
                .resourceChain(false); // 리소스 체인을 비활성화합니다.

        // OpenAPI 명세서 경로를 예외 처리합니다.
        registry.addResourceHandler("/v3/api-docs/**")
                .addResourceLocations("/v3/api-docs/")
                .resourceChain(false); // 리소스 체인을 비활성화합니다.
    }

}