package com.springSecurity.fundamentals.service;

import com.springSecurity.fundamentals.entity.UserEntity;
import com.springSecurity.fundamentals.repository.UserRepository;
import com.springSecurity.fundamentals.utility.classes.JwtUtility;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtUtility jwtUtility;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager, JwtUtility jwtUtility) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtUtility = jwtUtility;
    }

    public UserEntity registerUser(UserEntity userEntity) {
        userEntity.setId(null);
        userEntity.setPassword(passwordEncoder.encode(userEntity.getPassword()));
        return userRepository.save(userEntity);
    }

    public List<UserEntity> findAll() {
        return userRepository.findAll();
    }

    public String verifyUser(UserEntity userEntity) {
        String username = userEntity.getUsername();
        String password = userEntity.getPassword();

        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(username, password));

        if (authentication.isAuthenticated()) {
            return jwtUtility.generateJwtToken(username, password);
            //return "success";
        } else {
            return "Failed";
        }
    }
}
