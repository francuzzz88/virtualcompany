package ru.petrov.virtualcompany.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JwtManagerTest {

    private final JwtManager jwtManager = new JwtMangerJJwtImpl();

    public static final String jwtAccessSecret = "secret1";
    public static final String jwtRefreshSecret = "secret";
    public static final int jwtAccessExpiration = 15;
    public static final int jwtRefreshExpiration = 30 * 24 * 60;
    private User user;
    private String testToken;
    private String badTokenSignature;
    private String badTokenExpiration;

    @BeforeEach
    void setUp() {

        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("TADMIN"));
        authorities.add(new SimpleGrantedAuthority("TUSER"));

        user = (User) User.builder()
                .username("test")
                .password("12345")
                .authorities("ADMIN", "USER")
                .build();

        testToken = Jwts.builder()
                .setSubject("test")
                .setIssuedAt(new Date())
                .setExpiration(Date.from(LocalDateTime.now().plusMinutes(25).atZone(ZoneId.systemDefault()).toInstant()))
                .claim("roles", authorities)
                .signWith(SignatureAlgorithm.HS256, "secret")
                .compact();

        badTokenSignature = Jwts.builder()
                .setSubject("test")
                .setIssuedAt(new Date())
                .setExpiration(Date.from(LocalDateTime.now().plusMinutes(25).atZone(ZoneId.systemDefault()).toInstant()))
                .claim("roles", authorities)
                .signWith(SignatureAlgorithm.HS256, "badsecretkey")
                .compact();

        badTokenExpiration = Jwts.builder()
                .setSubject("test")
                .setIssuedAt(new Date())
                .setExpiration(Date.from(LocalDateTime.now().minusMinutes(30).atZone(ZoneId.systemDefault()).toInstant()))
                .claim("roles", authorities)
                .signWith(SignatureAlgorithm.HS256, "secret")
                .compact();
    }

    @Test
    void test_accessToken_usesUser() {
        String token = jwtManager.generatedJwtAccessToken(user);

        String subject = Jwts.parser().setSigningKey(jwtAccessSecret).parseClaimsJws(token).getBody().getSubject();
        Assertions.assertEquals(subject, user.getUsername());
    }

    @Test
    void test_accessToken_usesIssueDate() {
        String token = jwtManager.generatedJwtAccessToken(user);

        Date issuedAt = Jwts.parser().setSigningKey(jwtAccessSecret).parseClaimsJws(token).getBody().getIssuedAt();
        Assertions.assertNotNull(issuedAt);
    }

    @Test
    void test_accessToken_hasExpirationOf10Minutes() {
        String token = jwtManager.generatedJwtAccessToken(user);


        Claims claims = Jwts.parser()
                .setSigningKey(jwtAccessSecret)
                .parseClaimsJws(token)
                .getBody();
        Date issuedAt = claims.getIssuedAt();
        Date expiration = claims.getExpiration();
        Assertions.assertEquals(expiration.getTime() - issuedAt.getTime(), (jwtAccessExpiration * 60 * 1000L));
    }

    @Test
    void test_accessToken_hasUserRoles() {
        String accessToken = jwtManager.generatedJwtAccessToken(user);


        Claims claims = Jwts.parser()
                .setSigningKey(jwtAccessSecret)
                .parseClaimsJws(accessToken)
                .getBody();
        List<String> roles = parseClaims(claims);
        Assertions.assertEquals(roles.size(), 2);
        Assertions.assertEquals(roles.get(0), "ADMIN");
        Assertions.assertEquals(roles.get(1), "USER");
    }

    @Test
    void test_refreshToken_usesUser() {
        String token = jwtManager.generatedJwtRefreshToken(user);

        String subject = Jwts.parser().setSigningKey(jwtRefreshSecret).parseClaimsJws(token).getBody().getSubject();
        Assertions.assertEquals(subject, user.getUsername());
    }

    @Test
    void test_refreshToken_usesIssueDate() {
        String token = jwtManager.generatedJwtRefreshToken(user);

        Date issuedAt = Jwts.parser().setSigningKey(jwtAccessSecret).parseClaimsJws(token).getBody().getIssuedAt();
        Assertions.assertNotNull(issuedAt);
    }

    @Test
    void test_refreshToken_hasExpirationOf10Minutes() {
        String token = jwtManager.generatedJwtRefreshToken(user);


        Claims claims = Jwts.parser()
                .setSigningKey(jwtAccessSecret)
                .parseClaimsJws(token)
                .getBody();
        Date issuedAt = claims.getIssuedAt();
        Date expiration = claims.getExpiration();
        Assertions.assertEquals(expiration.getTime() - issuedAt.getTime(), (jwtRefreshExpiration * 60 * 1000L));
    }

    @Test
    void test_refreshToken_hasUserRoles() {
        String accessToken = jwtManager.generatedJwtAccessToken(user);


        Claims claims = Jwts.parser()
                .setSigningKey(jwtAccessSecret)
                .parseClaimsJws(accessToken)
                .getBody();
        List<String> roles = parseClaims(claims);
        Assertions.assertEquals(roles.size(), 2);
        Assertions.assertEquals(roles.get(0), "ADMIN");
        Assertions.assertEquals(roles.get(1), "USER");
    }

    @Test
    void verifyAccessToken() {
        User userParse = jwtManager.verifyAccessToken(testToken);

        assertEquals(userParse.getUsername(), "test");
        assertEquals(userParse.getAuthorities().size(), 2);
    }

    @Test
    void verifyTokenBadSignature() {
        assertThrows(SignatureException.class, () -> jwtManager.verifyAccessToken(badTokenSignature));

    }

    @Test
    void verifyTokenBadExpiration() {
        assertThrows(ExpiredJwtException.class,()-> jwtManager.verifyAccessToken(badTokenExpiration));

    }


    @Test
    void verifyRefreshToken() {
        User userParse = jwtManager.verifyRefreshToken(testToken);

        assertEquals(userParse.getUsername(), "test");
        assertEquals(userParse.getAuthorities().size(), 2);
    }

    private List<String> parseClaims(Claims claims) {
        var roles = claims.get("roles");

        var collection = new ObjectMapper()
                .convertValue(roles,
                        new TypeReference<ArrayList<HashMap<String, String>>>() {
                        });

        List<String> authorities = new ArrayList<>();

        collection.forEach(mapa -> authorities.addAll(mapa.values()));
        return authorities;
    }
}