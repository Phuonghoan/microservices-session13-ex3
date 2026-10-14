package org.example.identityservice.controller;

import org.example.identityservice.entity.User;
import org.example.identityservice.repository.UserRepository;
import org.example.identityservice.service.AuthService;
import org.example.identityservice.util.JwtUtil;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import org.springframework.security.authentication.BadCredentialsException;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;

    public AuthController(
            AuthService authService,
            UserRepository userRepository,
            JwtUtil jwtUtil
    ) {
        this.authService = authService;
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
    }

    // ==================================
    // BÀI 1: ĐĂNG KÝ
    // ==================================

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(
            @RequestBody RegisterRequest request
    ) {

        User user = authService.register(
                request.username(),
                request.password()
        );

        RegisterResponse response = new RegisterResponse(
                user.getId(),
                user.getUsername(),
                user.getRole()
        );

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(response);
    }

    // ==================================
    // BÀI 2: TEST JWT
    // ==================================

    @GetMapping(
            value = "/test-token",
            produces = MediaType.TEXT_PLAIN_VALUE
    )
    public String testToken(
            @RequestParam String username
    ) {

        User user = userRepository.findByUsername(username)
                .orElseThrow(() ->
                        new ResponseStatusException(
                                HttpStatus.NOT_FOUND,
                                "Không tìm thấy User: " + username
                        )
                );

        return jwtUtil.generateToken(user);
    }

    // ==================================
    // BÀI 3: LOGIN
    // ==================================

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @RequestBody LoginRequest request
    ) {

        String token = authService.login(
                request.username(),
                request.password()
        );

        return ResponseEntity.ok(
                new LoginResponse(token)
        );
    }

    // Xử lý lỗi đăng nhập
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleBadCredentials(
            BadCredentialsException exception
    ) {

        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(new ErrorResponse("Bad credentials"));
    }

    // ==================================
    // DTO
    // ==================================

    public record RegisterRequest(
            String username,
            String password
    ) {
    }

    public record RegisterResponse(
            String id,
            String username,
            String role
    ) {
    }

    public record LoginRequest(
            String username,
            String password
    ) {
    }

    public record LoginResponse(
            String token
    ) {
    }

    public record ErrorResponse(
            String message
    ) {
    }
}