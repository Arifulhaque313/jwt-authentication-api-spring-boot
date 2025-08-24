package com.ariful.jwtauth.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = ValidEmailValidator.class)
@Documented
public @interface ValidEmail {

    String message() default "Invalid email format";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
