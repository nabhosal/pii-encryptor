package io.github.nabhosal.pii;

import io.github.nabhosal.pii.encoder.Codec;

/**
 * <h1>PII Handler</h1>
 * The interface define api interaction for applying encryption and resolving encrypted data
 * <p>
 *
 * @author  Nilesh Bhosale
 * @since   2019-09-06
 */
public interface PIIHandler {
    /**
     * Apply method is used to encrypt PII data using defined codec
     * Internally it will used CodecLoader to load codec using codecCode
     *
     * @param json Raw input json
     * @param codecCode  Codec code used to encrypt json
     * @return encrypted field-level json by using codec
     */
    String apply(String json, String codecCode);
    /**
     * Apply method is used to encrypt PII data using passed codec
     * Internally it will bypass CodecLoader and instead use provided codec
     *
     * @param json Raw input json
     * @param codec  Codec used to encrypt json
     * @return encrypted field-level json by using codec
     */
    String apply(String json, Codec codec);
    /**
     * Resolve method is used to decrypt PII data using codec info available input data
     * Input json is field level encrypted with extra info such as
     *       DEK Data Encryption Key
     *       codec code for loading codec through CodecLoader
     *       KEKID DEK is encrypted using KEK (Key Encryption Key). KeyProvider use access KEK by using KEKID
     *
     * @param json Raw input json
     * @return decrypted all field-level json
     */
    String resolve(String json);
}
