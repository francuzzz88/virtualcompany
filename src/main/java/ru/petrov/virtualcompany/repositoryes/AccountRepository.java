package ru.petrov.virtualcompany.repositoryes;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import ru.petrov.virtualcompany.entitys.Account;

@Repository
public interface AccountRepository extends JpaRepository<Account, Integer> {

}
