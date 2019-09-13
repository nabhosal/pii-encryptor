package io.github.nabhosal.pii.exception;

public class CodecException extends RuntimeException {

    public CodecException(String message){
        super(message);
    }

    public CodecException(String message, Throwable exception){
        super(message, exception);
    }
}
