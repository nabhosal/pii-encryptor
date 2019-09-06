package io.github.nabhosal.pii.cipher;
/**
 * <h1>EncryptionService</h1>
 *  EncryptionService interface provide encryption service, it relies on KeyProvider to get KEK keys.
 *  EncryptionSession provide thread-safe context during encryption and decryption of multiple fields within documents
 *  For encryption use newSession method
 *  {@code EncryptionService.EncryptionSession session = service.newSession(); }
 *  For decryption, recreate session used to encrypt using eDEK and KEKId
 *  {@code EncryptionService.EncryptionSession session = service.buildSession(eDEK, KEKId); }
 * <p>
 *
 * @author  Nilesh Bhosale
 * @since   2019-09-06
 */
public interface EncryptionService {

    /**
     * The 'encrypt' method to encrypt raw data using EncryptionSession
     *
     * @param session EncryptionSession instance for encrypting raw data
     * @param raw raw data
     * @return encrypted raw data EncryptionSession
     */
    public String encrypt(EncryptionSession session, String raw);

    /**
     * The 'decrypt' method to decrypt cipher data using EncryptionSession
     *
     * @param session EncryptionSession instance for decrypting raw data
     * @param cipher cipher data
     * @return decrypted raw data EncryptionSession
     */
    public String decrypt(EncryptionSession session, String cipher);

    /**
     * Provide KeyProvider implementation instance
     * @return KeyProvider instance
     */
    public KeyProvider getKeyProvider();

    /**
     * Build EncryptionSession with eDEK and KEKId to recreate session used to encrypt the data.
     * The recreated session will be used in decryption of data
     *
     * @param eDEK encrypted DEK
     * @param KEKId KEK id for KEK reference
     * @return EncryptionSession
     */
    public EncryptionSession buildSession(String eDEK, String KEKId);

    /**
     * Create new EncryptionSession to encrypt the data.
     * It will create DEK, and assign KEKid using KeyProvider
     * @return EncryptionSession
     */
    public EncryptionSession newSession();

    /**
     * The EncryptionSession interface define, session context used to encrypt and decrypt across multiple field in documents
     */
    interface EncryptionSession{

        /**
         * Get Generated DEK
         * @return DEK
         */
        public String getDEK();

        /**
         * Get encrypted DEK using KEK
         * @return encrypted DEK
         */
        public String geteDEK();

        /**
         * Get KEK Key id used to encrypt the DEK
         * @return KEK Key ID
         */
        public String getKEKId();
    }
}
