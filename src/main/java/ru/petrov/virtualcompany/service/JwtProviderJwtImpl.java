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
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;

//@Component
public class JwtProviderJwtImpl implements JwtProvider {
    @Override
    public String generatedJwtAccessToken(User user) {
        String token = Jwts.builder()
                .setSubject(user.getUsername())
                .setExpiration(Date.from(LocalDateTime.now().plusHours(24).atZone(ZoneId.systemDefault()).toInstant()))
                .claim("roles", user.getAuthorities())
                .signWith(SignatureAlgorithm.HS512, "secret")
                .compact();
        return token;
    }

    @Override
    public String generatedJwtRefreshToken(User user) {
        String token = Jwts.builder()
                .setSubject(user.getUsername())
                .setExpiration(Date.from(LocalDateTime.now().plusMinutes(30).atZone(ZoneId.systemDefault()).toInstant()))
                .claim("roles", user.getAuthorities())
                .signWith(SignatureAlgorithm.HS512, "secret")
                .compact();
        return token;
    }

    @Override
    public User verifyToken(String token) {
        Claims claims = Jwts.parser().setSigningKey("secret").parseClaimsJws(token).getBody();
        String user = claims.getSubject();

        var roles = claims.get("roles");
        var collection = new ObjectMapper()
                .convertValue(roles,
                        new TypeReference<ArrayList<HashMap<String, String>>>() {});
        ArrayList<GrantedAuthority> authorities = new ArrayList<>();

        collection.forEach(map ->
                map.values().stream().
                        map(s -> authorities.add(new SimpleGrantedAuthority(s))));

        return new User(user, "", authorities);
    }

}
