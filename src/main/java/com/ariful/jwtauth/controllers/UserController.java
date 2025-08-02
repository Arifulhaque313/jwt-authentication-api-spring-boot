package com.ariful.jwtauth.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class UserController {

    @GetMapping("/")
    public String home() {
        return "Welcome!";
    }

    @GetMapping("/health-check")
    public String healthCheck(){
        return "Everything is Okay";
    }

    @GetMapping("/user/hello")
    public String user() {
        return "Hello User!";
    }

    @GetMapping("/admin/dashboard")
    public String admin() {
        return "Admin Dashboard";
    }
}
