package io.github.nabhosal.pii.exception;

public class KeyProviderException extends RuntimeException {

    public KeyProviderException(String message){
        super(message);
    }

    public KeyProviderException(String message, Throwable exception) {
        super(message, exception);
    }
}
