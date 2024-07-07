package com.example.demo.dto.user;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
@Schema(description = "회원가입 요청 Dto")
public class SignUpRequestDto {
    @NotBlank(message = "아이디는 필수입니다.")
    private String id;

    @NotBlank(message="비밀번호는 필수값입니다.")
    @Pattern(regexp = "(?=.*\\d)(?=.*[a-zA-Z])[0-9a-zA-Z]{4,16}", message = "4자 이상, 16자 이하의 영문, 숫자 조합")
    private String pw;

    @NotBlank(message = "이메일은 필수입니다.")
    @Email(message = "이메일 형식이 맞지 않습니다.")
    private String email;

    @NotBlank(message="닉네임은 필수값입니다.")
    @Pattern(regexp = "([a-zA-Z0-9ㄱ-ㅎ|ㅏ-ㅣ|가-힣]).{1,10}", message = "한글 or 영문자 or 숫자의 조합으로 1~10자리")
    private String nickname;

    @NotBlank(message = "휴대폰 번호 입력은 필수입니다.")
    private String phone;



}