package com.example.demo.domain;

import com.example.demo.enums.Role;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "uid")
    private Long uid;

    @Column(name = "username")
    private String username;

    @Column(name = "user_pw")
    private String pw;

    @Column(name = "email")
    private String email;

    @Column(name = "nickname")
    private String nickname;

    @Column(name = "role")
    private Role role;

    @Column(name = "phone")
    private String phone;

    @Column(name = "token")
    private String token;

    public void saveToken(String token) {
        this.token = token;
    }
}