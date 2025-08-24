package com.ariful.jwtauth.util;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.SecureRandom;

public final class PasswordUtil {

    private static final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(12);
    private static final SecureRandom secureRandom = new SecureRandom();

    private static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    private static final String DIGITS = "0123456789";
    private static final String SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?";
    private static final String ALL_CHARS = UPPERCASE + LOWERCASE + DIGITS + SPECIAL_CHARS;

    public static String encodePassword(String rawPassword) {
        return passwordEncoder.encode(rawPassword);
    }

    public static boolean matches(String rawPassword, String encodedPassword) {
        return passwordEncoder.matches(rawPassword, encodedPassword);
    }

    public static String generateRandomPassword(int length) {
        if (length < 8) {
            throw new IllegalArgumentException("Password length must be at least 8 characters");
        }

        StringBuilder password = new StringBuilder(length);

        // Ensure at least one character from each category
        password.append(UPPERCASE.charAt(secureRandom.nextInt(UPPERCASE.length())));
        password.append(LOWERCASE.charAt(secureRandom.nextInt(LOWERCASE.length())));
        password.append(DIGITS.charAt(secureRandom.nextInt(DIGITS.length())));
        password.append(SPECIAL_CHARS.charAt(secureRandom.nextInt(SPECIAL_CHARS.length())));

        // Fill the rest randomly
        for (int i = 4; i < length; i++) {
            password.append(ALL_CHARS.charAt(secureRandom.nextInt(ALL_CHARS.length())));
        }

        // Shuffle the password
        return shuffleString(password.toString());
    }

    private static String shuffleString(String input) {
        char[] chars = input.toCharArray();
        for (int i = chars.length - 1; i > 0; i--) {
            int j = secureRandom.nextInt(i + 1);
            char temp = chars[i];
            chars[i] = chars[j];
            chars[j] = temp;
        }
        return new String(chars);
    }

    private PasswordUtil() {
        // Utility class
    }
}
