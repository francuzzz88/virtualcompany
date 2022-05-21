package ru.petrov.virtualcompany.dtos.request;

import lombok.Data;

@Data
public class UserLogin {
    private String username;
    private String password;

}
