package com.ariful.jwtauth.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.util.regex.Pattern;

public class ValidEmailValidator implements ConstraintValidator<ValidEmail, String> {

    private static final String EMAIL_PATTERN =
            "^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$";

    private static final Pattern pattern = Pattern.compile(EMAIL_PATTERN);

    @Override
    public void initialize(ValidEmail constraintAnnotation) {
        // Initialization if needed
    }

    @Override
    public boolean isValid(String email, ConstraintValidatorContext context) {
        if (email == null || email.trim().isEmpty()) {
            return false;
        }

        return pattern.matcher(email).matches() && email.length() <= 100;
    }
}
