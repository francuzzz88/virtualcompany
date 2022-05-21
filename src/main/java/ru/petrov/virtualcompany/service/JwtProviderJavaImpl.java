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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

import static java.util.Arrays.stream;

@Component
public class JwtProviderJavaImpl implements JwtProvider {

    @Override
    public String generatedJwtAccessToken(User user) {
        Algorithm algorithm = Algorithm.HMAC256(SecurityConstants.jwtAccessSecret);
        String jwtAccessToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + SecurityConstants.jwtAccessExpiration))
                .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(algorithm);
        return jwtAccessToken;
    }

    @Override
    public String generatedJwtRefreshToken(User user) {
        Algorithm algorithm = Algorithm.HMAC256(SecurityConstants.jwtRefreshSecret);
        String jwtRefreshToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + SecurityConstants.jwtRefreshExpiration))
                .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(algorithm);
        return jwtRefreshToken;
    }

    @Override
    public User verifyToken(String token) {
        Algorithm algorithm = Algorithm.HMAC256(SecurityConstants.jwtAccessSecret);
        JWTVerifier verifier = JWT.require(algorithm).build();
        DecodedJWT decodedJWT = verifier.verify(token);
        String user = decodedJWT.getSubject();
        String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        stream(roles).forEach(r-> authorities.add(new SimpleGrantedAuthority(r)));
        return new User(user, "", authorities);
    }
}
