package com.example.demo.controller;

import org.springframework.stereotype.Component;
import java.util.Base64;
import java.util.Date;

@Component
public class JwtUtil {

  
    public String generateToken(String email, String role) {
        String token = email + ":" + role + ":" + new Date().getTime();
        return Base64.getEncoder().encodeToString(token.getBytes());
    }

    
    public String extractEmail(String token) {
        String decoded = new String(Base64.getDecoder().decode(token));
        return decoded.split(":")[0];  // email
    }

    
    public String extractRole(String token) {
        String decoded = new String(Base64.getDecoder().decode(token));
        return decoded.split(":")[1];  // role
    }

    
}
