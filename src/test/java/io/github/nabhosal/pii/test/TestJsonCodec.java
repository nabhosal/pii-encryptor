package io.github.nabhosal.pii.test;

import io.github.nabhosal.pii.PIIHandler;
import io.github.nabhosal.pii.cipher.KeyProvider;
import io.github.nabhosal.pii.cipher.impl.AESBasedEncryptionService;
import io.github.nabhosal.pii.cipher.EncryptionService;
import io.github.nabhosal.pii.cipher.impl.MapBasedKeyProviderImpl;
import io.github.nabhosal.pii.encoder.Codec;
import io.github.nabhosal.pii.encoder.CodecLoader;
import io.github.nabhosal.pii.encoder.impl.JsonBasedStandardCodec;
import io.github.nabhosal.pii.encoder.impl.StubCodecLoader;
import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.nabhosal.pii.PIIHandlerBuilder;
import org.junit.Test;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static io.github.nabhosal.pii.encoder.impl.JsonBasedStandardCodec.DEFAULT_CODECTYPE;
import static org.junit.Assert.assertNotEquals;

public class TestJsonCodec {

    static String input_json = "{\"name\":\"full name\",\"pan\":\"123124324\",\"pan_name\":\"pan full name\",\"mobile\":\"4534534534\",\"hello\":\"Hash\",\"nested\":{\"key1\":\"value1\",\"key2\":\"value2\"},\"arrays\":[{\"k1\":\"v1\",\"k2\":\"v2\"},{\"k1\":\"v11\",\"k2\":\"v21\"}]}";

    @Test
    public void testBasicWorking(){

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

        System.out.println(jsonInString2);

    }

    @Test
    public void testPIIHandler(){

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
        System.out.println(codec);
        System.out.println(piiHandler.apply(input_json, codec));

    }

    @Test
    public void testStubCodecLoader(){
        CodecLoader loader = new StubCodecLoader();
        System.out.println("test-code == > \n"+loader.loadByCode("test-code"));
        System.out.println("default == > \n"+loader.loadByCode(""));
    }

    @Test
    public void testRefinedAPI(){
        PIIHandler piiHandler = PIIHandlerBuilder.standard();
        String encrypteddata = piiHandler.apply(input_json, "test-code-imp");
        String decrypteddata = piiHandler.resolve(encrypteddata);

        System.out.println("orginaldata "+input_json);
        System.out.println("");
        System.out.println("encrypteddata1 "+encrypteddata);
        System.out.println("decrypteddata1 "+decrypteddata);

        encrypteddata = piiHandler.apply(input_json, "test-code-imp");
        decrypteddata = piiHandler.resolve(encrypteddata);

        System.out.println("");
        System.out.println("encrypteddata2 "+encrypteddata);
        System.out.println("decrypteddata2 "+decrypteddata);
    }

    @Test
    public void testPIIBuilderImpl(){

        PIIHandler piiHandler = PIIHandlerBuilder.withDefault()
                .withCodecLoader(new TestCodecLoader())
                .withEncryptionService(new TestEncryptionService())
                .build();
        String encrypteddata = piiHandler.apply(input_json, "test-codec");
        String decrypteddata = piiHandler.resolve(encrypteddata);
        System.out.println("orginaldata1 "+input_json);
        System.out.println("encrypteddata1 "+encrypteddata);
        System.out.println("decrypteddata1 "+decrypteddata);
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
        assertNotEquals(modifiedEncryptedData.equalsIgnoreCase(decrypteddata), "In absence of codec, input == output for resolve method");
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
            System.out.println("encrypteddata" + encrypteddata);
            modifiedEncryptedData = objectMapper.writeValueAsString(encryptDataMap);
        } catch (IOException e) {
            e.printStackTrace();
        }

        String decrypteddata = piiHandler.resolve(modifiedEncryptedData);
        assertNotEquals(modifiedEncryptedData.equalsIgnoreCase(decrypteddata), "In absence of DEK, input == output for resolve method");
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
            System.out.println("encrypteddata" + encrypteddata);
            modifiedEncryptedData = objectMapper.writeValueAsString(encryptDataMap);
        } catch (IOException e) {
            e.printStackTrace();
        }

        String decrypteddata = piiHandler.resolve(modifiedEncryptedData);
        assertNotEquals(modifiedEncryptedData.equalsIgnoreCase(decrypteddata), "In absence of DEK, input == output for resolve method");
    }

}
