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
public interface Codec{
    /**
     * Enforce Codec to return unique code
     *
     * @return code is unique identifier for Codec
     */
    public String getCode();
    /**
     * The 'apply' method is delegated from PIIHandler to apply encryption and hashing
     *
     * @param json input json
     * @param encryptionService used to encrypt the data
     * @return field-level encrypted data
     */
    public String apply(String json, EncryptionService encryptionService);
    /**
     * The 'resolve' method is delegated from PIIHandler to resolve decryption and removing hashing
     *
     * @param json input json
     * @param encryptionService used to decrypt the data
     * @return field-level decrypted data
     */
    public String resolve(String json, EncryptionService encryptionService);
}
