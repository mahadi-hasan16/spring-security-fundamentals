package com.springSecurity.fundamentals.controller;

import com.springSecurity.fundamentals.entity.UserEntity;
import com.springSecurity.fundamentals.service.UserService;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/user")
public class UserController {
    private final UserService userService;
    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public UserEntity createUser(@RequestBody UserEntity userEntity) {
        return this.userService.registerUser(userEntity);
    }

    @PostMapping("/login")
    public String login(@RequestBody UserEntity userEntity) {
        return userService.verifyUser(userEntity);
    }

    @GetMapping("/list")
    public List<UserEntity> listUsers() {
        return userService.findAll();
    }
}
