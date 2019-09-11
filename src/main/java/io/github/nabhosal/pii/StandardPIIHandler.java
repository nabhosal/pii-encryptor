package io.github.nabhosal.pii;

import io.github.nabhosal.pii.cipher.EncryptionService;
import io.github.nabhosal.pii.encoder.Codec;
import io.github.nabhosal.pii.encoder.CodecLoader;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
/**
 * <h1>StandardPIIHandler</h1>
 * StandardPIIHandler is default implementation of PIIHandler Interface.
 * It use CodecLoader to load codec, and EncryptionService to encrypt and decrypt the field level data
 * <p>
 *
 * @author  Nilesh Bhosale
 * @since   2019-09-06
 */
public class StandardPIIHandler implements PIIHandler {

    private final CodecLoader codecLoader;
    private final EncryptionService encryptionService;

    public StandardPIIHandler(CodecLoader codecLoader, EncryptionService encryptionService){

        this.codecLoader = codecLoader;
        this.encryptionService = encryptionService;
    }

    @Override
    public String apply(String json, String codecCode) {
        return apply(json, codecLoader.loadByCode(codecCode));
    }

    @Override
    public String apply(String json, Codec codec) {
        return codec.apply(json, encryptionService);
    }

    @Override
    public String resolve(String json) {

        String codecCode = codecLoader.infer(json);

        Codec codec = codecLoader.loadByCode(codecCode);

        return codec.resolve(json, encryptionService);
    }
}
