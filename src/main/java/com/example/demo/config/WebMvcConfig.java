package com.example.demo.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@RequiredArgsConstructor
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry){
        registry.addMapping("/**") // 모든 경로에 대해 cors 설정 적용
                .allowedOriginPatterns("*") // 모든 도메인에서 요청 허용
                .allowCredentials(true) // 클라이언트가 자격 증명 정보(cookie, HTTP 인증)를 포함하도록 허용
                .allowedMethods("*") //모든 HTTP 메서드(GET, POST 등)를 허용합니다
                .maxAge(3600); //요청의 유효 기간을 설정
    }

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        // Swagger UI 경로를 예외 처리.
        registry.addResourceHandler("/swagger-ui/**")
                .addResourceLocations("classpath:/META-INF/resources/webjars/springdoc-openapi-ui/")
                .resourceChain(false); // 리소스 체인 비활성화

        // OpenAPI 명세서 경로를 예외 처리.
        registry.addResourceHandler("/v3/api-docs/**")
                .addResourceLocations("/v3/api-docs/")
                .resourceChain(false); // 리소스 체인 비활성화
    }

}
