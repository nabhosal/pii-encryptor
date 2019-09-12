package io.github.nabhosal.pii.test;

import io.github.nabhosal.pii.PIIHandler;
import io.github.nabhosal.pii.cipher.KeyProvider;
import io.github.nabhosal.pii.cipher.impl.AESBasedEncryptionService;
import io.github.nabhosal.pii.cipher.EncryptionService;
import io.github.nabhosal.pii.cipher.impl.MapBasedKeyProviderImpl;
import io.github.nabhosal.pii.encoder.Codec;
import io.github.nabhosal.pii.encoder.CodecLoader;
import io.github.nabhosal.pii.encoder.impl.JsonBasedStandardCodec;
import io.github.nabhosal.pii.encoder.impl.DemoJsonCodecLoader;
import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.nabhosal.pii.PIIHandlerBuilder;
import org.junit.Test;

import java.io.*;
import java.util.*;

import static io.github.nabhosal.pii.encoder.impl.JsonBasedStandardCodec.DEFAULT_CODECTYPE;
import static junit.framework.TestCase.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

public class TestJsonCodec {

    private static String input_json = "{\"name\":\"full name\",\"pan\":\"123124324\",\"pan_name\":\"pan full name\",\"mobile\":\"4534534534\",\"hello\":\"Hash\",\"nested\":{\"key1\":\"value1\",\"key2\":\"value2\"},\"arrays\":[{\"k1\":\"v1\",\"k2\":\"v2\"},{\"k1\":\"v11\",\"k2\":\"v21\"}]}";

    @Test
    public void testJsonStandardCodec(){

        ObjectMapper objectMapper = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                .setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);

        JsonBasedStandardCodec codec = new JsonBasedStandardCodec();
        codec.encrypt("$.pan");
        codec.addHash("$.pan_name");
        codec.encrytWithHash("$.mobile");
        codec.setCode("test-code");
        codec.setCodecType(DEFAULT_CODECTYPE);

        String jsonInString2 = null;
        try {
            jsonInString2 = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(codec);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }

        assertTrue("Code not found in json string", jsonInString2.indexOf("test-code") > 0);
    }

    @Test
    public void testPIIHandlerApplyMethod(){

        PIIHandler piiHandler = PIIHandlerBuilder.standard();

        JsonBasedStandardCodec codec = new JsonBasedStandardCodec();
        codec.encrypt("$.pan");
        codec.addHash("$.pan_name");
        codec.addHash("$.nested.key1");
        codec.encrytWithHash("$.mobile");
        codec.addHash("$.arrays[0].k1");
        codec.encrypt("$.arrays[*].k2");
        codec.setCode("test-code");
        codec.setCodecType(DEFAULT_CODECTYPE);

        String encrypted = piiHandler.apply(input_json, codec);

        assertTrue("KEKID not found", encrypted.indexOf("KEKID") > 0);
        assertTrue("Code not found in encrypted datat", encrypted.indexOf("test-code") > 0);
        assertTrue("Hash for $.arrays[0].k1 not found", encrypted.indexOf("h_k1") > 0);
        assertTrue("Encrypt for pan field not found", encrypted.indexOf("pan") > 0);
    }

    @Test
    public void testStubCodecLoader(){

        CodecLoader loader = new DemoJsonCodecLoader();

        Codec codec = loader.loadByCode("test-code");
        assertTrue("Not able to load test-code", "test-code".equalsIgnoreCase(codec.getCode()));

        Codec defaultCodec = loader.loadByCode("");
        assertTrue("Not able to load default code", "default".equalsIgnoreCase(defaultCodec.getCode()));

    }

    @Test
    public void testRefinedAPI(){
        PIIHandler piiHandler = PIIHandlerBuilder.standard();
        String encrypteddata = piiHandler.apply(input_json, "test-code-imp");
        String decrypteddata = piiHandler.resolve(encrypteddata);

//        System.out.println("orginaldata "+input_json);
//        System.out.println("encrypteddata "+encrypteddata);
//        System.out.println("decrypteddata "+decrypteddata);

        assertTrue("decrypteddata is different from orginaldata", input_json.equalsIgnoreCase(decrypteddata));

        encrypteddata = piiHandler.apply(input_json, "test-code-imp");
        decrypteddata = piiHandler.resolve(encrypteddata);

//        System.out.println("encrypteddata2 "+encrypteddata);
//        System.out.println("decrypteddata2 "+decrypteddata);

        assertTrue("decrypteddata is different from orginaldata", input_json.equalsIgnoreCase(decrypteddata));
    }

    @Test
    public void testEncryptSession(){
        AESBasedEncryptionService service_with_default = new AESBasedEncryptionService(new MapBasedKeyProviderImpl());

        System.setProperty("kek-keys-path", "./src/main/resources/KEKkeys.json");
        AESBasedEncryptionService service_with_path = new AESBasedEncryptionService(new MapBasedKeyProviderImpl());
        System.out.println(service_with_path.newSession().getKEKId());
    }

    @Test
    public void testAbsenceOfCodecInEncryptedJson(){
        PIIHandler piiHandler = PIIHandlerBuilder.standard();
        String encrypteddata = piiHandler.apply(input_json, "test-code-imp");
        Map<String, Object> encryptDataMap = null;
        ObjectMapper objectMapper = new ObjectMapper();
        String modifiedEncryptedData = "";
        try {
            encryptDataMap = objectMapper.readValue(encrypteddata, Map.class);
            encryptDataMap.remove("codec");
            modifiedEncryptedData = objectMapper.writeValueAsString(encryptDataMap);
        } catch (IOException e) {
            e.printStackTrace();
        }

        String decrypteddata = piiHandler.resolve(modifiedEncryptedData);
        assertNotEquals("In absence of codec, input == output for resolve method", decrypteddata, modifiedEncryptedData);
    }

    @Test
    public void testAbsenceOfDEKInEncryptedJson(){
        PIIHandler piiHandler = PIIHandlerBuilder.standard();
        String encrypteddata = piiHandler.apply(input_json, "test-code-imp");
        Map<String, Object> encryptDataMap = null;
        ObjectMapper objectMapper = new ObjectMapper();
        String modifiedEncryptedData = "";
        try {
            encryptDataMap = objectMapper.readValue(encrypteddata, Map.class);
            encryptDataMap.remove("DEK");
            modifiedEncryptedData = objectMapper.writeValueAsString(encryptDataMap);
        } catch (IOException e) {
            e.printStackTrace();
        }

        String decrypteddata = piiHandler.resolve(modifiedEncryptedData);

        assertTrue("In absence of DEK, input == output for resolve method", modifiedEncryptedData.equalsIgnoreCase(decrypteddata));
    }

    @Test
    public void testAbsenceOfKEKInEncryptedJson(){
        PIIHandler piiHandler = PIIHandlerBuilder.standard();
        String encrypteddata = piiHandler.apply(input_json, "test-code-imp");
        Map<String, Object> encryptDataMap = null;
        ObjectMapper objectMapper = new ObjectMapper();
        String modifiedEncryptedData = "";
        try {
            encryptDataMap = objectMapper.readValue(encrypteddata, Map.class);
            encryptDataMap.remove("KEKID");
            modifiedEncryptedData = objectMapper.writeValueAsString(encryptDataMap);
        } catch (IOException e) {
            e.printStackTrace();
        }

        String decrypteddata = piiHandler.resolve(modifiedEncryptedData);

        assertTrue("In absence of DEK, input == output for resolve method", modifiedEncryptedData.equalsIgnoreCase(decrypteddata));
    }


    @Test
    public void testPIIBuilderImpl(){

        PIIHandler piiHandler = PIIHandlerBuilder.withDefault()
                .withCodecLoader(new TestCodecLoader())
                .withEncryptionService(new TestEncryptionService())
                .build();

        String encrypteddata = piiHandler.apply(input_json, "test-codec");
        String decrypteddata = piiHandler.resolve(encrypteddata);

        assertFalse("decrypteddata should not be same as orginaldata due to hardcoded value encryptionService", input_json.equalsIgnoreCase(decrypteddata));

    }

    static class TestCodecLoader implements CodecLoader{

        @Override
        public Codec loadByCode(String code) {

            JsonBasedStandardCodec codec = new JsonBasedStandardCodec();
            codec.encrypt("$.pan");
            codec.setCode("test-codec");
            codec.setCodecType(DEFAULT_CODECTYPE);

            return codec;
        }

        @Override
        public String infer(String cipher) {
            String codecStr = "";
            try {
                codecStr = new ObjectMapper().readTree(cipher).get("codec").asText("");
            } catch (IOException e) {
                System.out.println("DemoJsonCodecLoader: codec field not found");
                return cipher;
            } catch (NullPointerException e){
                System.out.println("DemoJsonCodecLoader: codec field not found");
                return cipher;
            }

            if("".equalsIgnoreCase(codecStr)){
                return cipher;
            }
            return codecStr;
        }
    }

    static class TestEncryptionService implements EncryptionService {


        @Override
        public String encrypt(EncryptionSession session, String raw) {
            return "encrypt";
        }

        @Override
        public String decrypt(EncryptionSession session, String cipher) {
            return "raw";
        }

        @Override
        public KeyProvider getKeyProvider() {
            return new KeyProvider(){

                HashMap<String, String> map = new HashMap<>();

                @Override
                public String getKeyById(String id) {
                    map.put(id, id);
                    return map.get(id);
                }

                @Override
                public String getKeyForEncryption(Map<String, Object> params) {

                    return "";
                }
            };
        }

        @Override
        public EncryptionSession buildSession(String eDEK, String KEKId) {
            return new TestEncryptionSessionImpl();
        }

        @Override
        public EncryptionSession newSession() {
            return new TestEncryptionSessionImpl();
        }

        static class TestEncryptionSessionImpl implements EncryptionSession{

            public TestEncryptionSessionImpl(){

            }

            @Override
            public String getDEK() {
                return "dek";
            }

            @Override
            public String geteDEK() {
                return "edk";
            }

            @Override
            public String getKEKId() {
                return "123";
            }

        }

    }
}
