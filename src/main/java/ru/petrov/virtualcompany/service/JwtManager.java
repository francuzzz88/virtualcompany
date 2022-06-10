package ru.petrov.virtualcompany.service;

import org.springframework.security.core.userdetails.User;

public interface JwtManager {
    String generatedJwtAccessToken(User user);
    String generatedJwtRefreshToken(User user);
    User verifyAccessToken(String token);
    User verifyRefreshToken(String token);
}
