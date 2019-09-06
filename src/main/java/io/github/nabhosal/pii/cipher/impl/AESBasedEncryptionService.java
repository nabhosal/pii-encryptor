package io.github.nabhosal.pii.cipher.impl;

import io.github.nabhosal.pii.cipher.EncryptionService;
import io.github.nabhosal.pii.cipher.KeyProvider;
import io.github.nabhosal.pii.util.AES;

import java.security.SecureRandom;
import java.util.*;

public class AESBasedEncryptionService implements EncryptionService {

    private final KeyProvider keyProvider;

    public AESBasedEncryptionService(KeyProvider keyProvider){

        Objects.requireNonNull(keyProvider);
        this.keyProvider = keyProvider;
    }

    @Override
    public String encrypt(EncryptionSession session, String raw) {
        return AES.encrypt(raw, session.getDEK());
    }

    @Override
    public String decrypt(EncryptionSession session, String cipher) {
        return AES.decrypt(cipher, session.getDEK());
    }

    @Override
    public KeyProvider getKeyProvider() {
        return this.keyProvider;
    }

    @Override
    public EncryptionSession newSession(){
        SecureRandom secureRandom = new SecureRandom();
        String DEK = String.valueOf(secureRandom.nextGaussian());
        String KEKId = getKeyProvider().getKeyForEncryption(null);
        String eDEK = AES.encrypt(DEK, keyProvider.getKeyById(KEKId));
        return new EncryptionSessionImpl(DEK, eDEK, KEKId);
    }

    @Override
    public EncryptionSession buildSession(String eDEK, String KEKId){

        String DEK = AES.decrypt(eDEK, getKeyProvider().getKeyById(KEKId));
        return new EncryptionSessionImpl(DEK, eDEK, KEKId);
    }

    static class EncryptionSessionImpl implements EncryptionService.EncryptionSession {

        private final String DEK;
        private final String eDEK;
        private final String KEKId;

        public EncryptionSessionImpl(String DEK, String eDEK, String KEKId){
            this.DEK = DEK;
            this.eDEK = eDEK;
            this.KEKId = KEKId;
        }

        @Override
        public String getDEK() {
            return DEK;
        }

        @Override
        public String geteDEK() {
            return eDEK;
        }

        @Override
        public String getKEKId() {
            return KEKId;
        }
    }
}
