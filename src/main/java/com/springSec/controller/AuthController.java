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
    public ResponseEntity<?> userSignIn(@RequestBody LoginDto loginDto) throws UnsupportedEncodingException {
        Optional<User> userOpt = userRepository.findByUsername(loginDto.getUsername());
        if (userOpt.isPresent()) {
            User user = userOpt.get();

            // ✅ Verify password
            boolean match = BCrypt.checkpw(loginDto.getPassword(), user.getPassword());
            if (match) {
                // ✅ Automatically generate OTP instead of returning token immediately
                String otp = otpService.generateOtp(user.getMobile());

                // ✅ For demo: return OTP in response (in production, send via SMS/email)
                return ResponseEntity.ok("OTP sent to registered mobile: " + user.getMobile() + " (Demo OTP: " + otp + ")");
            }
        }

        return new ResponseEntity<>("Invalid credentials", HttpStatus.UNAUTHORIZED);

    /*
    // 🔴 Old code - directly returning token on password verification
    String token = userService.verifyLogin(loginDto);
    if (token != null) {
        TokenDto dto = new TokenDto();
        dto.setToken(token);
        dto.setTokenType("JWT");
        return new ResponseEntity<>(dto, HttpStatus.CREATED);
    }
    return new ResponseEntity<>("Invalid Password ", HttpStatus.BAD_GATEWAY);
    */
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
    public ResponseEntity<?> validateOtp(@RequestParam String mobile, @RequestParam String otp) {
        try {
            // 1. Validate OTP
            if (!otpService.validateOtp(mobile, otp)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body("Invalid OTP or OTP expired");
            }

            // 2. Find user by mobile number
            Optional<User> userOptional = userRepository.findByMobile(mobile);
            if (userOptional.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body("User not found with this mobile number");
            }

            // 3. Generate JWT token directly using JwtService
            User user = userOptional.get();
            String jwtToken = jwtService.generateToken(user.getUsername(), user.getRole());
            String refreshToken = generateRefreshToken.createRefreshToken(user);

            // 4. Create response
            TokenDto tokenResponse = new TokenDto();
            tokenResponse.setTokenType("Bearer");
            tokenResponse.setToken(jwtToken);
            tokenResponse.setRefreshToken(refreshToken);
            // If you want to include expiration time, you can get it from JwtService's expiry field
            tokenResponse.setExpiresIn(jwtService.getExpiryInSeconds()); // Using the new method

            return ResponseEntity.ok(tokenResponse);

        } catch (UnsupportedEncodingException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Token generation error");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("An error occurred during OTP validation");
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

}
