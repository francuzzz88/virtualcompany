package ru.petrov.virtualcompany.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;

@Component
public class JwtMangerJJwtImpl implements JwtManager {

    public static final String jwtAccessSecret = "secret1";
    public static final String jwtRefreshSecret = "secret";
    public static final int jwtAccessExpiration = 15;
    public static final int jwtRefreshExpiration = 30 * 24 * 60;


    @Override
    public String generatedJwtAccessToken(User user) {
        return generatedJwtToken(user, jwtAccessExpiration, jwtAccessSecret);
    }

    @Override
    public String generatedJwtRefreshToken(User user) {
        return generatedJwtToken(user, jwtRefreshExpiration, jwtRefreshSecret);
    }

    @Override
    public User verifyAccessToken(String token) {
        return verifyToken(token, jwtAccessSecret);
    }

    @Override
    public User verifyRefreshToken(String token) {
        return verifyToken(token, jwtRefreshSecret);
    }
    private User verifyToken(String token, String jwtSecret) {
        Claims claims = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody();
        String user = claims.getSubject();

        var roles = claims.get("roles");
        var collection = new ObjectMapper()
                .convertValue(roles,
                        new TypeReference<ArrayList<HashMap<String, String>>>() {
                        });

        ArrayList<GrantedAuthority> authorities = new ArrayList<>();
        collection.forEach(map -> map.values().forEach(s -> authorities.add(new SimpleGrantedAuthority(s))));

        return new User(user, "", authorities);
    }

    private String generatedJwtToken(User user, int jwtExpiration, String jwtSecret) {
        return Jwts.builder()
                .setSubject(user.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(Date.from(LocalDateTime.now().plusMinutes(jwtExpiration).atZone(ZoneId.systemDefault()).toInstant()))
                .claim("roles", user.getAuthorities())
                .signWith(SignatureAlgorithm.HS256, jwtSecret)
                .compact();
    }

}
