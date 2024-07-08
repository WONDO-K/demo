package com.example.demo.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Arrays;

/**
 * Swagger 설정 클래스.
 */
@OpenAPIDefinition(
        info = @Info(title = "Demo API 명세서",
                description = "Demo API 명세서",
                version = "v1"))
@Configuration
public class SwaggerConfig {

    /**
     * OpenAPI 빈을 등록.
     *
     * @return OpenAPI 객체
     */
    @Bean
    public OpenAPI openAPI(){
        // 보안 스키마 설정
        SecurityScheme securityScheme = new SecurityScheme()
                .type(SecurityScheme.Type.HTTP)   // 보안 스키마의 타입 설정 (HTTP)
                .scheme("bearer")                // 사용할 인증 방식 설정 (bearer)
                .bearerFormat("JWT")             // bearer 토큰의 포맷 설정 (JWT)
                .in(SecurityScheme.In.HEADER)    // 헤더에 토큰을 포함시킬 것을 설정
                .name("Authorization");          // 헤더의 이름 설정 (Authorization)

        // 보안 요구사항 설정
        SecurityRequirement securityRequirement = new SecurityRequirement().addList("bearerAuth");

        // OpenAPI 객체 생성 및 설정
        return new OpenAPI()
                .components(new Components().addSecuritySchemes("bearerAuth", securityScheme)) // 보안 스키마를 추가합니다.
                .security(Arrays.asList(securityRequirement)); // 보안 요구사항을 설정합니다.
    }

}