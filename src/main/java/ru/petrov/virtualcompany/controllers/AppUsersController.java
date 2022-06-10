package ru.petrov.virtualcompany.controllers;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import ru.petrov.virtualcompany.dtos.request.RoleUserForm;
import ru.petrov.virtualcompany.entitys.AppRole;
import ru.petrov.virtualcompany.entitys.AppUser;
import ru.petrov.virtualcompany.service.AppUserService;

import java.util.List;

@RestController
@Slf4j
public class AppUsersController {

    private final AppUserService userService;

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
    @PreAuthorize("hasAuthority('ADMIN')")
    public AppRole addNewRole(@RequestBody AppRole appRole) {
        return userService.addNewRole(appRole);
    }

    @PostMapping("/addroletouser")
    @PreAuthorize("hasAuthority('ADMIN')")
    public void addRoleToUser(@RequestBody RoleUserForm roleUserForm) {
        userService.addRoleToUser(roleUserForm.getUsername(), roleUserForm.getRoleName());
    }
}




