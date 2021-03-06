package ru.petrov.virtualcompany.entitys;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Collection;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AppUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    private String username;
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String password;
    private String email;
    @ManyToMany(fetch = FetchType.EAGER)
    private Collection<AppRole> userRoles = new ArrayList<>();
    @OneToOne
    @JoinColumn(name = "account_id")
    private Account account;
}
