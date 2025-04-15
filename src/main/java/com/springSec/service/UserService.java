package com.springSec.service;

import com.springSec.entity.User;
import com.springSec.payload.LoginDto;
import com.springSec.repo.UserRepository;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {

   private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public boolean verifyLogin(LoginDto loginDto){
        Optional<User> byUsername = userRepository.findByUsername(loginDto.getUsername());
       if (byUsername.isPresent()){
           User user = byUsername.get();

           return BCrypt.checkpw(loginDto.getPassword(),user.getPassword());
       }
       return false;

    }

}
