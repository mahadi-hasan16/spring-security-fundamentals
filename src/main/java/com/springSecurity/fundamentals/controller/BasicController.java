package com.springSecurity.fundamentals.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class BasicController {
    @GetMapping("/hello")
    public String hello() {
        return "hello";
    }

    @GetMapping("/csrf")
    public CsrfToken getCsrf(CsrfToken csrfToken) {
        return csrfToken;
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String admin() {
        return "I AM ADMIN";
    }
    
    @GetMapping("/user")
    @PreAuthorize("hasRole('USER')")
    public String user() {
        return "I AM USER";
    }
}
