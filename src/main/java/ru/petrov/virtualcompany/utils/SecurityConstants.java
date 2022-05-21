package ru.petrov.virtualcompany.utils;

public class SecurityConstants {

    public static final String jwtAccessSecret="secret";
    public static final String jwtRefreshSecret="secret";
    public static final int jwtAccessExpiration = 15*60*1000;
    public static final int jwtRefreshExpiration = 24*60*60*1000;


}
