package com.springSec.securityService;

import com.springSec.entity.RefreshToken;
import com.springSec.entity.User;
import com.springSec.repo.RefreshTokenRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
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

    @Transactional
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


    // Delete a specific refresh token
    public void deleteByToken(String token) {
        refreshTokenRepository.findByToken(token).ifPresent(refreshTokenRepository::delete);
        System.out.println("Refresh token deleted from database");
    }

    // Delete all refresh tokens for a user (useful for password changes)
    public void deleteAllForUser(User user) {
        refreshTokenRepository.deleteAllByUser(user);
        System.out.println("All refresh tokens deleted for user: " + user.getUsername());
    }

    // Clean up expired tokens periodically
    @Scheduled(fixedRate = 24 * 60 * 60 * 1000) // Runs daily
    public void cleanupExpiredTokens() {
        Instant now = Instant.now();
        refreshTokenRepository.deleteAllByExpiryDateBefore(now);
        System.out.println("Cleaned up expired refresh tokens");
    }
}
