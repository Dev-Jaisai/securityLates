package com.springSec.controller;

import com.springSec.entity.User;
import com.springSec.payload.LoginDto;
import com.springSec.payload.TokenDto;
import com.springSec.repo.UserRepository;
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

    public AuthController(UserRepository userRepository, PasswordEncoder passwordEncoder, UserService userService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.userService = userService;
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
        String token = userService.verifyLogin(loginDto);
        if (token != null) {

            TokenDto dto= new TokenDto();
            dto.setToken(token);
            dto.setTokenType("JWT");
            return new ResponseEntity<>(dto, HttpStatus.CREATED);
        }
        return new ResponseEntity<>("Invalid Password ", HttpStatus.BAD_GATEWAY);

    }
    @GetMapping("/hi")
    public String getmessage(){
        return "hi hello";
    }
}
