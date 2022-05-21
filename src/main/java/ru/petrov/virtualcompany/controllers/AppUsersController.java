package ru.petrov.virtualcompany.controllers;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import ru.petrov.virtualcompany.dtos.request.RoleUserForm;
import ru.petrov.virtualcompany.entitys.AppRole;
import ru.petrov.virtualcompany.entitys.AppUser;
import ru.petrov.virtualcompany.service.AppUserService;
import ru.petrov.virtualcompany.service.JwtProvider;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@RestController
@Slf4j
public class AppUsersController {

    private final AppUserService userService;
    @Autowired
    private JwtProvider jwtProvider;

    public AppUsersController(AppUserService userService) {
        this.userService = userService;
    }

    @GetMapping("/users")
    public List<AppUser> listUsers() {
        return userService.listUsers();
    }

    @PostMapping("/users")
    public AppUser addNewUser(@RequestBody AppUser appUser) {
        return userService.addNewUser(appUser);
    }

    @PostMapping("/role")
    public AppRole addNewRole(@RequestBody AppRole appRole) {
        return userService.addNewRole(appRole);
    }

    @PostMapping("/addroletouser")
    public void addRoleToUser(@RequestBody RoleUserForm roleUserForm) {
        userService.addRoleToUser(roleUserForm.getUsername(), roleUserForm.getRoleName());
    }

    @GetMapping("/refresh")
    public void refreshToken(HttpServletRequest request,
                             HttpServletResponse response) throws IOException {
        String authorizationToken = request.getHeader(AUTHORIZATION);
        if (authorizationToken != null && authorizationToken.startsWith("Bearer ")) {

            try {
                String jwt = authorizationToken.substring(7);
                UserDetails userDetails = jwtProvider.verifyToken(jwt);

                User user = userService.loadUserByUsername(userDetails.getUsername());

                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(userDetails.getUsername(), null, userDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);

                Map<String, String> idToken = new HashMap<>();
                idToken.put("access-token", jwtProvider.generatedJwtAccessToken(user));
                idToken.put("refresh-token", jwtProvider.generatedJwtRefreshToken(user));
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), idToken);

            } catch (IllegalArgumentException | JWTVerificationException e) {
                log.error(e.getMessage());
                response.setHeader("error-message", e.getMessage());
                response.sendError(HttpServletResponse.SC_FORBIDDEN);
            }

        } else {
            throw new RuntimeException("refresh token required");
        }
    }
}




