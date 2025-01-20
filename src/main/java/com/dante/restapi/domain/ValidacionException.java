package com.dante.restapi.domain;

public class ValidacionException extends RuntimeException {

    public ValidacionException(String mensaje) {
        super(mensaje);
    }
}
