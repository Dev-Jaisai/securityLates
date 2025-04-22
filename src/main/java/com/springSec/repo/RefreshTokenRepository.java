package com.springSec.repo;

import com.springSec.entity.RefreshToken;
import com.springSec.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);
    void deleteByUser(User user);
    void deleteByToken(String token);

    void deleteAllByUser(User user);

    void deleteAllByExpiryDateBefore(Instant now);
}
