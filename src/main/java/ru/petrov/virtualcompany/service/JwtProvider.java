package ru.petrov.virtualcompany.service;

import org.springframework.security.core.userdetails.User;

public interface JwtProvider {
    String generatedJwtAccessToken(User user);
    String generatedJwtRefreshToken(User user);
    User verifyToken(String token);
}
