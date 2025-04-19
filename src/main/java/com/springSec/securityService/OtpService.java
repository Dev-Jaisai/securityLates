package com.springSec.securityService;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class OtpService {

    // Store OTPs with their expiration time (key: username/email, value: OTP and expiration time)
    private final Map<String, OtpData> otpStorage = new ConcurrentHashMap<>();

    // OTP validity duration in milliseconds (5 minutes)
    private static final long OTP_VALID_DURATION = 5 * 60 * 1000;

    // OTP length
    private static final int OTP_LENGTH = 6;

    /**
     * Generates and stores a new OTP for the given key (username/email)
     * @param key The mobileNumber to associate with the OTP
     * @return The generated OTP (for demo purposes - in production, this should be sent directly to user)
     */
    public String generateOtp(String mobileNumber) {
        // Clean up any existing OTP for this key
        otpStorage.remove(mobileNumber);

        // Generate random OTP
        String otp = generateRandomOtp();

        // Calculate expiration time
        long expirationTime = System.currentTimeMillis() + OTP_VALID_DURATION;

        // Store the OTP with its expiration time
        otpStorage.put(mobileNumber, new OtpData(otp, expirationTime));

        return otp;
    }

    /**
     * Validates the provided OTP for the given key
     * @param key The username or email
     * @param otp The OTP to validate
     * @return true if valid, false otherwise
     */
    public boolean validateOtp(String key, String otp) {
        OtpData otpData = otpStorage.get(key);

        // No OTP found for this key
        if (otpData == null) {
            return false;
        }

        // Check if OTP matches and is not expired
        if (otpData.getOtp().equals(otp) && System.currentTimeMillis() <= otpData.getExpirationTime()) {
            // Remove the OTP after successful validation
            otpStorage.remove(key);
            return true;
        }

        return false;
    }

    /**
     * Cleans up expired OTPs periodically
     */
    @Scheduled(fixedRate = 60 * 1000) // Run every minute
    public void cleanupExpiredOtps() {
        long currentTime = System.currentTimeMillis();
        otpStorage.entrySet().removeIf(entry ->
                entry.getValue().getExpirationTime() <= currentTime
        );
    }

    /**
     * Generates a random numeric OTP
     * @return The generated OTP string
     */
    private String generateRandomOtp() {
        Random random = new Random();
        StringBuilder otp = new StringBuilder(OTP_LENGTH);

        for (int i = 0; i < OTP_LENGTH; i++) {
            otp.append(random.nextInt(10)); // 0-9
        }

        return otp.toString();
    }

    /**
     * Inner class to hold OTP data and expiration time
     */
    private static class OtpData {
        private final String otp;
        private final long expirationTime;

        public OtpData(String otp, long expirationTime) {
            this.otp = otp;
            this.expirationTime = expirationTime;
        }

        public String getOtp() {
            return otp;
        }

        public long getExpirationTime() {
            return expirationTime;
        }
    }
}