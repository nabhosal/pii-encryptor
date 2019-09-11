package io.github.nabhosal.pii.encoder;

import io.github.nabhosal.pii.cipher.EncryptionService;

/**
 * <h1>Codec</h1>
 * Codec provide metadata on field level details on encryption or hashing,
 * it define how EncryptionService should encrypt the data
 * Each codec must have code, a unique identifier
 * <p>
 *
 * @author  Nilesh Bhosale
 * @since   2019-09-06
 */
public interface Codec<T>{
    /**
     * Enforce Codec to return unique code
     *
     * @return code is unique identifier for Codec
     */
    public String getCode();
    /**
     * The 'apply' method is delegated from PIIHandler to apply encryption and hashing
     *
     * @param rawdata input raw data
     * @param encryptionService used to encrypt the data
     * @return field-level encrypted data
     */
    public String apply(String rawdata, EncryptionService encryptionService);
    /**
     * The 'resolve' method is delegated from PIIHandler to resolve decryption and removing hashing
     *
     * @param cipher input cipher data
     * @param encryptionService used to decrypt the data
     * @return field-level decrypted data
     */
    public String resolve(String cipher, EncryptionService encryptionService);

    public Codec encrypt(T field);

    public Codec addHash(T field);

    public Codec encrytWithHash(T field);

    public Codec setCode(String code);
}
