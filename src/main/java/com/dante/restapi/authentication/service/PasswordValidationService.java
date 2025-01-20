package com.dante.restapi.authentication.service;

import com.dako.forohub.infra.exceptions.PasswordValidationException;
import org.springframework.stereotype.Service;

@Service
public class PasswordValidationService {

    public void validatePassword(String password) {
        if (password.length() < 8 || password.length() > 11 ||
                !password.matches(".*[A-Z].*") ||
                !password.matches(".*\\d.*")) {
            throw new PasswordValidationException(
                    "Password must be between 8 and 11 characters long, contain at least one uppercase letter and one number");
        }
    }
}