package ru.petrov.virtualcompany.repositoryes;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.petrov.virtualcompany.entitys.AppRole;

public interface AppRoleRepository extends JpaRepository<AppRole, Integer> {
    AppRole findByRoleName(String roleName);
}
