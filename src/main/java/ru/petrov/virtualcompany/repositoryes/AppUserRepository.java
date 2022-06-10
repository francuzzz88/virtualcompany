package ru.petrov.virtualcompany.repositoryes;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.petrov.virtualcompany.entitys.AppUser;

public interface AppUserRepository extends JpaRepository<AppUser, Integer> {
    AppUser findByUsername(String username);
    void deleteAppUserByUsername(String username);
}
