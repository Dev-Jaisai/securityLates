package com.springSec.securityService;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class OtpService {
    private final Map<String, OtpData> otpStorage = new ConcurrentHashMap<>();
    private static final long OTP_VALID_DURATION = 5 * 60 * 1000; // 5 minutes
    private static final int OTP_LENGTH = 6;

    public String generateOtp(String username) {
        // Clean up expired OTPs first
        cleanupExpiredOtps();

        // Generate and store new OTP
        String otp = generateRandomOtp();
        long expirationTime = System.currentTimeMillis() + OTP_VALID_DURATION;
        otpStorage.put(username, new OtpData(otp, expirationTime));

        System.out.println("Generated OTP for " + username + ": " + otp);
        System.out.println("Current OTP Storage: " + otpStorage);
        return otp;
    }

    public boolean validateOtp(String username, String otp) {
        System.out.println("Validating OTP for " + username + ", input: " + otp);
        System.out.println("Current OTP Storage: " + otpStorage);

        OtpData otpData = otpStorage.get(username);
        if (otpData == null) {
            System.out.println("No OTP found for user: " + username);
            return false;
        }

        boolean isValid = otpData.getOtp().equals(otp) &&
                System.currentTimeMillis() <= otpData.getExpirationTime();

        if (isValid) {
            otpStorage.remove(username); // Only remove if valid
            System.out.println("OTP validation successful for " + username);
        } else {
            System.out.println("OTP validation failed for " + username);
        }

        return isValid;
    }

    @Scheduled(fixedRate = 60 * 1000)
    public void cleanupExpiredOtps() {
        long currentTime = System.currentTimeMillis();
        otpStorage.entrySet().removeIf(entry ->
                entry.getValue().getExpirationTime() <= currentTime
        );
    }

    private String generateRandomOtp() {
        Random random = new Random();
        StringBuilder otp = new StringBuilder(OTP_LENGTH);
        for (int i = 0; i < OTP_LENGTH; i++) {
            otp.append(random.nextInt(10));
        }
        return otp.toString();
    }

    private static class OtpData {
        private final String otp;
        private final long expirationTime;

        public OtpData(String otp, long expirationTime) {
            this.otp = otp;
            this.expirationTime = expirationTime;
        }

        public String getOtp() { return otp; }
        public long getExpirationTime() { return expirationTime; }
    }
}