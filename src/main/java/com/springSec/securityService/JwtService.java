package com.springSec.securityService;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.springSec.entity.RefreshToken;
import com.springSec.entity.User;
import com.springSec.repo.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.UnsupportedEncodingException;
import java.util.Date;
import java.util.UUID;

@Service
public class JwtService {

    private final RefreshTokenRepository refreshTokenRepository;
    @Value("${jwt.key}")
    private String algorithmKey;


    @Value("${jwt.issuer}")
    private String issuer;


    @Value("${jwt.expiry}")
    private int expiry;

    public JwtService(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }


    /*CRICES Sign
     * create withIssuer withClaims  withExpiresAt withSubject sign*/
    public String generateToken(String username, String role) throws UnsupportedEncodingException {
        return JWT.create()
                .withClaim("role", role)
                .withIssuer(issuer)
                .withExpiresAt(new Date(System.currentTimeMillis() + expiry))
                .withSubject(username)
                .sign(Algorithm.HMAC256(algorithmKey));
    }

    /*RAB-VS
     * requires algorith build verify getSubject*/
    public String getUsername(String jwtToken) throws UnsupportedEncodingException {
        return JWT.require(Algorithm.HMAC256(algorithmKey))
                .withIssuer(issuer)
                .build()
                .verify(jwtToken)
                .getSubject();
    }

    /**
     * Returns the token expiration time in milliseconds
     */
    public int getExpiryInMillis() {
        return expiry;
    }

    /**
     * Returns the token expiration time in seconds
     * (More commonly used in API responses)
     */
    public int getExpiryInSeconds() {
        return expiry / 1000;
    }



}
