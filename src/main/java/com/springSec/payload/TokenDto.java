package com.springSec.payload;

import lombok.Data;

@Data
public class TokenDto {
    private String token;
    private String tokenType;
    private long expiresIn;        // Token expiration time in seconds

}

