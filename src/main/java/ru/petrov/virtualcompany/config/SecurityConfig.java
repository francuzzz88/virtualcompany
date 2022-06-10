package ru.petrov.virtualcompany.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import ru.petrov.virtualcompany.filters.JwtAuthenticationFilter;
import ru.petrov.virtualcompany.filters.JwtAuthorizationFilter;
import ru.petrov.virtualcompany.filters.JwtRefreshTokenFilter;
import ru.petrov.virtualcompany.service.AppUserService;
import ru.petrov.virtualcompany.service.JwtManager;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final AppUserService appUserDetailsService;
    private final JwtManager jwtManager;
    private final PasswordEncoder passwordEncoder;

    public SecurityConfig(AppUserService appUserDetailsService, JwtManager jwtManager, PasswordEncoder passwordEncoder) {
        this.appUserDetailsService = appUserDetailsService;
        this.jwtManager = jwtManager;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(appUserDetailsService).passwordEncoder(passwordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.headers().frameOptions().disable();
        http.authorizeRequests().antMatchers("/h2-console/**").permitAll();
        http.authorizeRequests().antMatchers(POST, "/users/**").hasAuthority("ADMIN");
        http.authorizeRequests().antMatchers(GET, "/users/**").hasAnyAuthority("ADMIN", "USER");
        http.authorizeRequests().anyRequest().authenticated();
        http.exceptionHandling().authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED));
        http.addFilter(new JwtAuthenticationFilter(authenticationManagerBean(), jwtManager));
        http.addFilterBefore(new JwtAuthorizationFilter(jwtManager), UsernamePasswordAuthenticationFilter.class);
        http.addFilterAfter(new JwtRefreshTokenFilter(appUserDetailsService, jwtManager), JwtAuthorizationFilter.class);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }



}
