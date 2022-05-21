package ru.petrov.virtualcompany.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import ru.petrov.virtualcompany.service.JwtProvider;
import ru.petrov.virtualcompany.service.JwtProviderJavaImpl;

@Configuration
public class ApplicationConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

//    @Bean
//    public JwtProvider provider(){
//        return new JwtProviderJavaImpl();
//    }

}
