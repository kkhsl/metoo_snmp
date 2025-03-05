package com.metoo.utils;

public class SNMPException extends Exception {
    public SNMPException(String message) {
        super(message);
    }

    public SNMPException(String message, Throwable cause) {
        super(message, cause);
    }
}