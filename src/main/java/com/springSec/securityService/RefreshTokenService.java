package com.springSec.securityService;

import com.springSec.entity.RefreshToken;
import com.springSec.entity.User;
import com.springSec.repo.RefreshTokenRepository;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    // Expiry: 7 days in milliseconds
    private final long refreshTokenDurationMs = 7 * 24 * 60 * 60 * 1000L;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }
    public String createRefreshToken(User user) {
        // Optional: remove old refresh token (if only one active per user)
        refreshTokenRepository.deleteByUser(user);

        // Create new token
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setUser(user);
        refreshToken.setExpiryDate(new Date(System.currentTimeMillis() + refreshTokenDurationMs));

        // Save to DB
        refreshTokenRepository.save(refreshToken);

        // Return only the token string
        return refreshToken.getToken();
    }

    /**
     * Finds refresh token from DB by token string.
     */
    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    /**
     * Checks if the token is expired.
     */
    public boolean isExpired(RefreshToken token) {
        return token.getExpiryDate().before(new Date());
    }

    /**
     * Deletes a specific refresh token (used if expired or logout).
     */
    public void delete(RefreshToken token) {
        refreshTokenRepository.delete(token);
    }

    /**
     * Deletes all refresh tokens of a user (optional - for logout all devices).
     */
    public void deleteByUser(User user) {
        refreshTokenRepository.deleteByUser(user);
    }
}
