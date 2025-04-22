package com.springSec.service;

import com.springSec.entity.User;
import com.springSec.payload.LoginDto;
import com.springSec.repo.UserRepository;
import com.springSec.securityService.JwtService;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Service;

import java.io.UnsupportedEncodingException;
import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;

    private final JwtService jwtService;


    public UserService(UserRepository userRepository, JwtService jwtService) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
    }

    public boolean verifyLogin(LoginDto loginDto) throws UnsupportedEncodingException {
        Optional<User> byUsername = userRepository.findByUsername(loginDto.getUsername());
        if (byUsername.isPresent()) {
            User user = byUsername.get();

            boolean checkpw = BCrypt.checkpw(loginDto.getPassword(), user.getPassword());

          /*  if (checkpw) {
                String tokenFromTheJwtService = jwtService.generateToken(user.getUsername(),user.getRole());
                return tokenFromTheJwtService;

            }*/

            return checkpw;
        }
        return false;

    }

}
