package org.example.identityservice.service;

import org.example.identityservice.entity.User;
import org.example.identityservice.repository.UserRepository;
import org.example.identityservice.util.JwtUtil;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;

import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtUtil jwtUtil
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    // ==================================
    // BÀI 1: ĐĂNG KÝ
    // ==================================

    public User register(String username, String password) {

        if (username == null || username.isBlank()
                || password == null || password.isBlank()) {

            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Username và password không được để trống"
            );
        }

        if (userRepository.existsByUsername(username)) {

            throw new ResponseStatusException(
                    HttpStatus.CONFLICT,
                    "Username đã tồn tại"
            );
        }

        User user = new User();

        user.setId(UUID.randomUUID().toString());
        user.setUsername(username);

        // Mã hóa BCrypt
        user.setPassword(passwordEncoder.encode(password));

        user.setRole("USER");

        return userRepository.save(user);
    }

    // ==================================
    // BÀI 3: ĐĂNG NHẬP
    // ==================================

    public String login(String username, String password) {

        // Kiểm tra thông tin đầu vào
        if (username == null || username.isBlank()
                || password == null || password.isBlank()) {

            throw new BadCredentialsException("Bad credentials");
        }

        // Tìm User từ PostgreSQL
        User user = userRepository.findByUsername(username)
                .orElseThrow(() ->
                        new BadCredentialsException("Bad credentials")
                );

        // So sánh mật khẩu bằng BCrypt
        if (!passwordEncoder.matches(
                password,
                user.getPassword()
        )) {

            throw new BadCredentialsException("Bad credentials");
        }

        // Đúng thông tin -> tạo JWT
        return jwtUtil.generateToken(user);
    }
}
