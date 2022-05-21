package ru.petrov.virtualcompany.dtos.request;

import lombok.Data;

@Data
public class UserSignIn {

    private String username;
    private String password;
    private String email;

}
