package ru.petrov.virtualcompany.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import ru.petrov.virtualcompany.entitys.AppRole;
import ru.petrov.virtualcompany.entitys.AppUser;

import java.util.List;

public interface AppUserService extends UserDetailsService{
    AppUser addNewUser(AppUser appUser);
    AppRole addNewRole(AppRole appRole);
    void addRoleToUser(String username, String roleName);
    List<AppUser> listUsers();
    User loadUserByUsername(String username);
}
