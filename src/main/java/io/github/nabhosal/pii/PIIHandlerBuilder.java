package io.github.nabhosal.pii;

import io.github.nabhosal.pii.cipher.impl.AESBasedEncryptionService;
import io.github.nabhosal.pii.cipher.EncryptionService;
import io.github.nabhosal.pii.cipher.impl.MapBasedKeyProviderImpl;
import io.github.nabhosal.pii.encoder.CodecLoader;
import io.github.nabhosal.pii.encoder.impl.StubCodecLoader;

/**
 * <h1>PIIHandlerBuilder</h1>
 * It is used to build StandardPIIHandler instance with configurable CodecLoader and EncryptionService
 * The standard method, will use default implementation such as
 * StubCodecLoader impl class of CodecLoader for loading the stubs,
 * AESBasedEncryptionService impl class of EncryptionService for encrypting and decrypting field level data using AES
 * MapBasedKeyProviderImpl impl class of KeyProvider for loading different KEK keys
 * We encourage to re-use the above class based on different use case
 * <p>
 *
 * @author  Nilesh Bhosale
 * @since   2019-09-06
 */

public class PIIHandlerBuilder{

    private CodecLoader codecLoader;
    private EncryptionService encryptionService;

    private PIIHandlerBuilder(CodecLoader codecLoader, EncryptionService encryptionService){
        this.codecLoader = codecLoader;
        this.encryptionService = encryptionService;
    }
    /**
     * it return StandardPIIHandler impl with default impl such as StubCodecLoader and AESBasedEncryptionService
     *
     * @return StandardPIIHandler instance
     */
    public static PIIHandler standard(){
        return withDefault().build();
    }

    /**
     * it return PIIHandlerBuilder instance with default impl such as StubCodecLoader and AESBasedEncryptionService
     *
     * @return PIIHandlerBuilder instance
     */
    public static PIIHandlerBuilder withDefault(){
        return new PIIHandlerBuilder(new StubCodecLoader(), new AESBasedEncryptionService(new MapBasedKeyProviderImpl()));
    }

    /**
     * it return StandardPIIHandler impl with CodecLoader and EncryptionService provided in PIIHandlerBuilder instance
     *
     * @return StandardPIIHandler instance
     */
    public PIIHandler build(){
        return new StandardPIIHandler(this.codecLoader, this.encryptionService);
    }

    /**
     * Set Custom CodecLoader in PIIHandlerBuilder instance
     * @param codecLoader codeLoader instance
     * @return PIIHandlerBuilder instance
     */
    public PIIHandlerBuilder withCodecLoader(CodecLoader codecLoader){
        this.codecLoader = codecLoader;
        return this;
    }

    /**
     * Set Custom EncryptionService in PIIHandlerBuilder instance
     * @param service EncryptionService instance
     * @return PIIHandlerBuilder instance
     */
    public PIIHandlerBuilder withEncryptionService(EncryptionService service){
        this.encryptionService = service;
        return this;
    }
}
