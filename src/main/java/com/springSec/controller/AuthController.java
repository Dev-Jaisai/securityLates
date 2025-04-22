package com.springSec.controller;

import com.springSec.entity.RefreshToken;
import com.springSec.entity.User;
import com.springSec.payload.LoginDto;
import com.springSec.payload.RefreshTokenDto;
import com.springSec.payload.TokenDto;
import com.springSec.repo.UserRepository;
import com.springSec.securityService.JwtService;
import com.springSec.securityService.OtpService;
import com.springSec.securityService.RefreshTokenService;
import com.springSec.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.io.UnsupportedEncodingException;
import java.util.Optional;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final UserService userService;

    private final OtpService otpService;

    private final JwtService jwtService;

    private final RefreshTokenService generateRefreshToken;


    public AuthController(UserRepository userRepository, PasswordEncoder passwordEncoder, UserService userService, OtpService otpService, JwtService jwtService, RefreshTokenService generateRefreshToken) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.userService = userService;
        this.otpService = otpService;
        this.jwtService = jwtService;
        this.generateRefreshToken = generateRefreshToken;
    }

    /*these method is for all user which is open for all*/
    @PostMapping("/register")
    public ResponseEntity<String> createUser(@RequestBody User user) {
        Optional<User> existingUser = userRepository.findByUsername(user.getUsername());
        if (existingUser.isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Username already exists");
        }
        Optional<User> existingEmailUser = userRepository.findByEmail(user.getEmail());
        if (existingEmailUser.isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Email already exists");
        }
     /*   String encode = passwordEncoder.encode(user.getPassword());
        user.setPassword(encode);;*/
        String gensalt = BCrypt.gensalt(10);
        String hashpw = BCrypt.hashpw(user.getPassword(), gensalt);
        user.setPassword(hashpw);
        user.setRole("ROLE_USER");
        userRepository.save(user);
        return ResponseEntity.status(HttpStatus.CREATED).body("User Created");

    }/*THese method is for content manager*/

    @PostMapping("/registerContentManager")
    public ResponseEntity<String> registerContentManager(@RequestBody User user) {
        Optional<User> existingUser = userRepository.findByUsername(user.getUsername());
        if (existingUser.isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Username already exists");
        }

        Optional<User> existingEmailUser = userRepository.findByEmail(user.getEmail());
        if (existingEmailUser.isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Email already exists");
        }
     /*   String encode = passwordEncoder.encode(user.getPassword());
        user.setPassword(encode);;*/
        String gensalt = BCrypt.gensalt(10);
        String hashpw = BCrypt.hashpw(user.getPassword(), gensalt);
        user.setPassword(hashpw);
        user.setRole("ROLE_CONTENT_MANAGER");

        userRepository.save(user);
        return ResponseEntity.status(HttpStatus.CREATED).body("User Created");
    }
    @PostMapping("/verify")
    public ResponseEntity<?> userSignIn(@RequestBody LoginDto loginDto) {
        Optional<User> userOpt = userRepository.findByUsername(loginDto.getUsername());
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }

        User user = userOpt.get();
        if (!BCrypt.checkpw(loginDto.getPassword(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }

        // Generate and return OTP
        String otp = otpService.generateOtp(user.getUsername());
        return ResponseEntity.ok("OTP sent to registered mobile: " + user.getMobile() +
                " (Demo OTP: " + otp + ")");
    }
    @GetMapping("/hi")
    public String getmessage() {
        return "hi hello";
    }

    @GetMapping("/hiUser")
    public String getMessagerUser() {
        return "hi hello from user";
    }

    @PostMapping("/generate")
    public ResponseEntity<?> generate(@RequestParam String phone) {

        Optional<User> userFindByMobile = userRepository.findByMobile(phone);

        if (userFindByMobile.isPresent()) {
            String otp = otpService.generateOtp(phone);
            return ResponseEntity.ok("OTP generated: " + otp + " Mobile Number: " + phone); // for demo only
        }
        return new ResponseEntity<>("User Not found", HttpStatus.BAD_REQUEST);

    }

    @PostMapping("/validate")
    public ResponseEntity<?> validateOtp(@RequestParam String username,
                                         @RequestParam String otp) {
        try {
            // 1. Validate OTP
            if (!otpService.validateOtp(username, otp)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body("Invalid OTP or OTP expired");
            }

            // 2. Get user details
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // 3. Generate tokens
            String jwtToken = jwtService.generateToken(user.getUsername(), user.getRole());
            String refreshToken = generateRefreshToken.createRefreshToken(user);

            // 4. Return response
            TokenDto tokenResponse = new TokenDto();
            tokenResponse.setTokenType("Bearer");
            tokenResponse.setToken(jwtToken);
            tokenResponse.setRefreshToken(refreshToken);
            tokenResponse.setExpiresIn(jwtService.getExpiryInSeconds());

            return ResponseEntity.ok(tokenResponse);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error during OTP validation: " + e.getMessage());
        }
    }
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshAccessToken(@RequestBody RefreshTokenDto request) {
        String requestToken = request.getRefreshToken();

        return generateRefreshToken.findByToken(requestToken)
                .map(refreshToken -> {
                    if (generateRefreshToken.isExpired(refreshToken)) {
                        generateRefreshToken.delete(refreshToken); // cleanup
                        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Refresh token expired");
                    }

                    User user = refreshToken.getUser();
                    String newAccessToken;
                    try {
                        newAccessToken = jwtService.generateToken(user.getUsername(), user.getRole());
                    } catch (Exception e) {
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Token generation failed");
                    }

                    TokenDto response = new TokenDto();
                    response.setTokenType("Bearer");
                    response.setToken(newAccessToken);
                    response.setExpiresIn(jwtService.getExpiryInSeconds());
                    response.setRefreshToken(requestToken); // reuse existing refresh token

                    return ResponseEntity.ok(response);
                })
                .orElse(ResponseEntity.status(HttpStatus.NOT_FOUND).body("Refresh token not found"));
    }
    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            @RequestBody RefreshTokenDto refreshTokenDto
/*
            @RequestHeader("Authorization") String authHeader
*/
    ) {
        try {
            // 1. Extract and validate the refresh token
            String refreshToken = refreshTokenDto.getRefreshToken();
            if (refreshToken == null || refreshToken.isBlank()) {
                return ResponseEntity.badRequest().body("Refresh token is required");
            }

            // 2. Delete the refresh token from database
            generateRefreshToken.deleteByToken(refreshToken);
/*

            // 3. (Optional) Add access token to blacklist
            String accessToken = authHeader.substring(7); // Remove "Bearer " prefix
            generateRefreshToken.blacklistToken(accessToken);
*/

            return ResponseEntity.ok("Logged out successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Logout failed: " + e.getMessage());
        }
    }
}
