package com.ariful.jwtauth.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.passay.*;

import java.util.Arrays;

public class ValidPasswordValidator implements ConstraintValidator<ValidPassword, String> {

    private PasswordValidator validator;

    @Override
    public void initialize(ValidPassword constraintAnnotation) {
        validator = new PasswordValidator(Arrays.asList(
                // Length rule - between 8 and 128 characters
                new LengthRule(8, 128),

                // At least one uppercase character
                new CharacterRule(EnglishCharacterData.UpperCase, 1),

                // At least one lowercase character
                new CharacterRule(EnglishCharacterData.LowerCase, 1),

                // At least one digit
                new CharacterRule(EnglishCharacterData.Digit, 1),

                // At least one special character
                new CharacterRule(EnglishCharacterData.Special, 1),

                // No whitespace characters
                new WhitespaceRule(),

                // Reject common passwords
                new IllegalSequenceRule(EnglishSequenceData.Alphabetical, 4, false),
                new IllegalSequenceRule(EnglishSequenceData.Numerical, 4, false),
                new IllegalSequenceRule(EnglishSequenceData.USQwerty, 4, false)
        ));
    }

    @Override
    public boolean isValid(String password, ConstraintValidatorContext context) {
        if (password == null) {
            return false;
        }

        RuleResult result = validator.validate(new PasswordData(password));

        if (result.isValid()) {
            return true;
        }

        // Add custom validation messages
        context.disableDefaultConstraintViolation();
        for (String message : validator.getMessages(result)) {
            context.buildConstraintViolationWithTemplate(message)
                    .addConstraintViolation();
        }

        return false;
    }
}