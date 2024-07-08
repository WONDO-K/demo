package com.example.demo.service;

import com.example.demo.domain.User;
import com.example.demo.repository.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * 사용자 정보를 데이터베이스에서 가져와 Spring Security에서 필요한 UserDetails를 구현하는 서비스 클래스.
 */
@Component("userDetailsService")
@AllArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    /**
     * 사용자 이름(username)을 기반으로 데이터베이스에서 사용자 정보를 조회하여 UserDetails 인터페이스를 구현.
     *
     * @param username 조회할 사용자의 이름
     * @return UserDetails 인터페이스를 구현한 객체
     * @throws UsernameNotFoundException 주어진 사용자 이름에 해당하는 사용자를 찾을 수 없는 경우 발생
     */
    @Override
    public UserDetails loadUserByUsername(final String username) {
        return userRepository.findByUsername(username)
                .map(user -> createUser(username, user))
                .orElseThrow(() -> new UsernameNotFoundException(username + " -> DB에서 찾을 수 없습니다."));
    }

    /**
     * 사용자 정보를 기반으로 UserDetails 객체를 생성.
     *
     * @param username 조회된 사용자의 이름
     * @param user     조회된 사용자의 정보(User 엔티티)
     * @return 생성된 UserDetails 객체
     */
    private org.springframework.security.core.userdetails.User createUser(String username, User user) {
        // 사용자 권한을 담을 리스트
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();

        // 사용자의 역할을 SimpleGrantedAuthority로 변환하여 리스트에 추가
        // SimpleGrantedAuthorit = Spring Security에서 권한을 나타내는 클래스
        // 데이터베이스에서 조회한 사용자의 역할 정보를 Spring Security가 이해할 수 있는 형태로 변환하여 권한 리스트에 추가하는 과정.
        grantedAuthorities.add(new SimpleGrantedAuthority(user.getRole().toString()));

        // UserDetails 객체 생성하여 반환
        return new org.springframework.security.core.userdetails.User(username, user.getPw(), grantedAuthorities);
    }
}
