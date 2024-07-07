package com.example.demo.dto.user;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
@Schema(description = "로그인 요청 Dto")
public class LoginRequestDto {
    @NotBlank
    private String username;
    @NotBlank
    private String pw;
}
