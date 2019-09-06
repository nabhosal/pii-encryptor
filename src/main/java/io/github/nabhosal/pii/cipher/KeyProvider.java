package io.github.nabhosal.pii.cipher;

import java.util.Map;
/**
 * <h1>KeyProvider</h1>
 * KeyProvider Interface define how to access KEK from external sources such as files, db,
 * or even through java class
 * KeyProvider is a delegation interface provided to define EncryptionService interaction with PIIHandler
 * Refer MapBasedKeyProviderImpl for loading keys from files
 * <p>
 *
 * @author  Nilesh Bhosale
 * @since   2019-09-06
 */
public interface KeyProvider {

    /**
     * The getKeyById method implementation will return kEK key by referring KEK Key id
     *
     * @param id kEK key id
     * @return KEK String
     */
    String getKeyById(String id);

    /**
     * The 'getKeyForEncryption' method is used to implement strategy to retrieve keyid for encryption
     * Strategy specifics key selection based on different requirements such key rotation policy, key usability, etc
     *
     * @param params inputs for strategy algorithm
     * @return keyId
     */
    String getKeyForEncryption(Map<String, Object> params);
}
