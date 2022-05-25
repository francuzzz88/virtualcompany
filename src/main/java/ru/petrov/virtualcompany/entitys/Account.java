package ru.petrov.virtualcompany.entitys;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Entity
@Data
@NoArgsConstructor
public class Account {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    private String firstname;
    private String lastname;
    private String username;
    private String email;
    @OneToOne
    @JoinColumn(name = "app_user_id")
    @JsonIgnore
    private AppUser appUser;


}
