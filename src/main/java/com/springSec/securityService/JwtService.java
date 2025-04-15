package com.springSec.securityService;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class JwtService {
    @Value("${jwt.key}")
    private String algorithmKey;


    @Value("${jwt.issuer}")
    private String issuer;


    @Value("${jwt.expiry}")
    private int expiry;
}
