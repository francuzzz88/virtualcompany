package ru.petrov.virtualcompany.filters;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import ru.petrov.virtualcompany.service.AppUserService;
import ru.petrov.virtualcompany.service.JwtManager;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Slf4j
@Component
public class JwtRefreshTokenFilter extends OncePerRequestFilter {


    private final AppUserService userService;

    private final JwtManager jwtManager;

    public JwtRefreshTokenFilter(AppUserService userService, JwtManager jwtManager) {
        this.userService = userService;
        this.jwtManager = jwtManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        if (!request.getServletPath().equals("/refresh")) {
            filterChain.doFilter(request, response);
        } else {
            String authorizationToken = request.getHeader(AUTHORIZATION);

            if (authorizationToken != null && authorizationToken.startsWith("Bearer ")) {

                try {
                    String jwt = authorizationToken.substring(7);
                    UserDetails userDetails = jwtManager.verifyRefreshToken(jwt);

                    User user = userService.loadUserByUsername(userDetails.getUsername());

                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(userDetails.getUsername(), null, userDetails.getAuthorities());
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);

                    Map<String, String> idToken = new HashMap<>();
                    idToken.put("access-token", jwtManager.generatedJwtAccessToken(user));
                    idToken.put("refresh-token", jwtManager.generatedJwtRefreshToken(user));
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    new ObjectMapper().writeValue(response.getOutputStream(), idToken);
                } catch (IllegalArgumentException | SignatureException | JWTVerificationException |
                         ExpiredJwtException | IOException e) {
                    log.error(e.getMessage());
                    response.setHeader("error-message", e.getMessage());
                    response.sendError(HttpServletResponse.SC_FORBIDDEN);
                }

            } else {
                filterChain.doFilter(request, response);
            }
        }
    }
}
