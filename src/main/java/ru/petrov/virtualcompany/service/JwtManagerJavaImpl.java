package ru.petrov.virtualcompany.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import ru.petrov.virtualcompany.utils.SecurityConstants;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.UUID;
import java.util.stream.Collectors;

import static java.util.Arrays.stream;

//@Component
public class JwtManagerJavaImpl implements JwtManager {

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

    private String generatedJwtToken(User user, int jwtExpiration, String jwtSecret) {
        Algorithm algorithm = Algorithm.HMAC256(jwtSecret);
        return JWT.create()
                .withSubject(user.getUsername())
                .withJWTId(UUID.randomUUID().toString())
                .withIssuedAt(new Date())
                .withExpiresAt(Date.from(LocalDateTime.now().plusMinutes(jwtExpiration).atZone(ZoneId.systemDefault()).toInstant()))
                .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(algorithm);
    }
    private User verifyToken(String token, String jwtSecret) {
        Algorithm algorithm = Algorithm.HMAC256(jwtSecret);
        JWTVerifier verifier = JWT.require(algorithm).build();
        DecodedJWT decodedJWT = verifier.verify(token);
        String user = decodedJWT.getSubject();
        String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        stream(roles).forEach(r -> authorities.add(new SimpleGrantedAuthority(r)));
        return new User(user, "", authorities);
    }
}
