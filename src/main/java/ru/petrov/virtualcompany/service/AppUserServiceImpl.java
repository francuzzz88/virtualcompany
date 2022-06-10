package ru.petrov.virtualcompany.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.petrov.virtualcompany.entitys.AppRole;
import ru.petrov.virtualcompany.entitys.AppUser;
import ru.petrov.virtualcompany.repositoryes.AppRoleRepository;
import ru.petrov.virtualcompany.repositoryes.AppUserRepository;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service
@Transactional
@RequiredArgsConstructor
public class AppUserServiceImpl implements AppUserService {

    private final AppUserRepository userRepository;
    private final AppRoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public AppUser addNewUser(AppUser appUser) {
        String password = appUser.getPassword();
        appUser.setPassword(passwordEncoder.encode(password));
        return userRepository.save(appUser);
    }

    @Override
    public AppRole addNewRole(AppRole appRole) {
        return roleRepository.save(appRole);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        AppUser appUser = userRepository.findByUsername(username);
        AppRole appRole = roleRepository.findByRoleName(roleName);
        appUser.getUserRoles().add(appRole);
    }

    @Override
    public User loadUserByUsername(String username) {

        AppUser appUser = userRepository.findByUsername(username);
        if (appUser == null) {
            throw new UsernameNotFoundException("User not found in data base");
        }
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        appUser.getUserRoles().forEach(appRole -> authorities.add(new SimpleGrantedAuthority(appRole.getRoleName())));
        return new User(appUser.getUsername(), appUser.getPassword(), authorities);
    }

    @Override
    public List<AppUser> listUsers() {
        return userRepository.findAll();
    }
}
