package ru.petrov.virtualcompany;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.password.PasswordEncoder;
import ru.petrov.virtualcompany.entitys.AppRole;
import ru.petrov.virtualcompany.entitys.AppUser;
import ru.petrov.virtualcompany.service.AppUserService;

import java.util.ArrayList;

@SpringBootApplication
public class VirtualCompanyApplication {

   @Autowired
   private PasswordEncoder passwordEncoder;

    public static void main(String[] args) {
        SpringApplication.run(VirtualCompanyApplication.class, args);
    }

//        @Bean
//    CommandLineRunner run(AppUserService userService) {
//        return args -> {
//            userService.addNewRole(new AppRole(null, "USER"));
//            userService.addNewRole(new AppRole(null, "ADMIN"));
//            userService.addNewRole(new AppRole(null, "MANAGER"));
//
//            userService.addNewUser(new AppUser(null, "user1", passwordEncoder.encode("1234"), "user1@email.ru", new ArrayList<>()));
//            userService.addNewUser(new AppUser(null, "admin", passwordEncoder.encode("1234"), "admin@email.ru", new ArrayList<>()));
//            userService.addNewUser(new AppUser(null, "user2", passwordEncoder.encode("1234"), "user2@email.ru", new ArrayList<>()));
//
//            userService.addRoleToUser("user1", "USER");
//            userService.addRoleToUser("admin", "USER");
//            userService.addRoleToUser("admin", "ADMIN");
//            userService.addRoleToUser("user2", "USER");
//            userService.addRoleToUser("user2", "MANAGER");
//        };
//    }

}
