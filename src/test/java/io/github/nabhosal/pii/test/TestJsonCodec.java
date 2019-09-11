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
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVPrinter;
import org.apache.commons.csv.CSVRecord;
import org.junit.Test;

import java.io.*;
import java.util.*;

import static io.github.nabhosal.pii.encoder.impl.JsonBasedStandardCodec.DEFAULT_CODECTYPE;
import static org.junit.Assert.assertNotEquals;

public class TestJsonCodec {

    static String input_json = "{\"name\":\"full name\",\"pan\":\"123124324\",\"pan_name\":\"pan full name\",\"mobile\":\"4534534534\",\"hello\":\"Hash\",\"nested\":{\"key1\":\"value1\",\"key2\":\"value2\"},\"arrays\":[{\"k1\":\"v1\",\"k2\":\"v2\"},{\"k1\":\"v11\",\"k2\":\"v21\"}]}";
    static String input_csv = "Rajeev Kumar Singh,\"rajeevs@example.com\",+91-9999999999,India\n" +
            "Sachin Tendulkar,sachin@example.com,+91-9999999998,India\n" +
            "Barak Obama,barak.obama@example.com,+1-1111111111,United States\n" +
            "Donald Trump,donald.trump@example.com,+1-2222222222,United States";


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

        @Override
        public String infer(String cipher) {
            String codecStr = "";
            try {
                codecStr = new ObjectMapper().readTree(cipher).get("codec").asText("");
            } catch (IOException e) {
                System.out.println("StubCodecLoader: codec field not found");
                return cipher;
            } catch (NullPointerException e){
                System.out.println("StubCodecLoader: codec field not found");
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

    @Test
    public void testCSVbyField(){
        PIIHandler piiHandler = PIIHandlerBuilder.withDefault().withCodecLoader(new CSVByFieldIndexCodecLoader()).build();
        String encrypteddata = piiHandler.apply(input_csv, "test-01");
        System.out.println("encrypteddata \n\n"+encrypteddata);
        String decrypteddata = piiHandler.resolve(encrypteddata);
        System.out.println("decrypteddata \n\n"+decrypteddata);
        System.out.println("Originaldata \n\n"+input_csv);
    }

    static class CSVByFieldIndexCodecLoader implements CodecLoader{

        private final HashMap<String, Codec> codecMap = new HashMap<>();

        public CSVByFieldIndexCodecLoader(){
            CSVByFieldIndexStandardCodec c1 = new CSVByFieldIndexStandardCodec();
            c1.addHash(2);
            c1.encrypt(0);
            c1.setCode("test-01");

            codecMap.put(c1.getCode(), c1);
        }


        @Override
        public Codec loadByCode(String code) {
            return codecMap.get(code);
        }

        @Override
        public String infer(String cipher) {

            CSVParser csvParser = null;
            String code = "";

            try {
                csvParser = CSVParser.parse(cipher, CSVFormat.DEFAULT.withSkipHeaderRecord());
                CSVRecord first = csvParser.getRecords().get(0);
                code = first.get(first.size() - 1);
            } catch (IOException e) {
                e.printStackTrace();
            }

            if ("".equalsIgnoreCase(code))
                return cipher;

            return code;
        }
    }

    static class CSVByFieldIndexStandardCodec implements Codec<Integer>{

        private String code;
        private String codecType;
        public static final String DEFAULT_CODECTYPE = "csv_byindex_01";
        private Set<Integer> efields;
        private Set<Integer> hfields;

        public CSVByFieldIndexStandardCodec(){
            efields = new LinkedHashSet<>();
            hfields = new LinkedHashSet<>();
        }

        @Override
        public String getCode() {
            return code;
        }

        @Override
        public String apply(String rawdata, EncryptionService encryptionService) {

            EncryptionService.EncryptionSession session = encryptionService.newSession();

            CSVParser csvParser = null;
            StringWriter csvInString = new StringWriter();
            CSVPrinter writer = null;

            try {
                csvParser = CSVParser.parse(rawdata, CSVFormat.DEFAULT.withSkipHeaderRecord());
                writer = new CSVPrinter(csvInString, CSVFormat.DEFAULT.withSkipHeaderRecord());
                for (CSVRecord csvRecord : csvParser) {
                    int totalFields = csvRecord.size();
                    List<String> list = new ArrayList<String>(totalFields + hfields.size() + 3);

                    for(String field : csvRecord)
                        list.add(field);

                    for(int fieldIndex : hfields)
                        list.add(DigestUtils.sha256Hex(list.get(fieldIndex)));

                    for(int fieldIndex : efields)
                        list.set(fieldIndex, encryptionService.encrypt(session, list.get(fieldIndex)));

                    list.add(session.geteDEK());
                    list.add(session.getKEKId());
                    list.add(DEFAULT_CODECTYPE);
                    list.add(getCode());

                    writer.printRecord(list);
                }

                writer.close(true);
                return csvInString.toString();
            } catch (IOException e) {
                e.printStackTrace();
            }

            return rawdata;
        }

        @Override
        public String resolve(String cipher, EncryptionService encryptionService) {

            EncryptionService.EncryptionSession session = null;

            CSVParser csvParser = null;
            StringWriter csvInString = new StringWriter();
            CSVPrinter writer = null;

            try {
                csvParser = CSVParser.parse(cipher, CSVFormat.DEFAULT.withSkipHeaderRecord());
                writer = new CSVPrinter(csvInString, CSVFormat.DEFAULT.withSkipHeaderRecord());

                CSVParser forInfer = CSVParser.parse(cipher, CSVFormat.DEFAULT.withSkipHeaderRecord());
                CSVRecord first = forInfer.getRecords().get(0);
                String eDEK = first.get(first.size() - 4);
                String KEKId = first.get(first.size() - 3);

                session = encryptionService.buildSession(eDEK, KEKId);

                for (CSVRecord csvRecord : csvParser) {

                    int totalFields = csvRecord.size() - hfields.size() - 3 - 1;

                    List<String> list = new ArrayList<String>(csvRecord.size());
                    for(int i = 0; i < totalFields ; i++){

                        if( efields.contains(i)){
                            list.add(encryptionService.decrypt(session, csvRecord.get(i)));
                        }else
                            list.add(csvRecord.get(i));
                    }

                    writer.printRecord(list);
                }

                writer.close(true);
                return csvInString.toString();
            } catch (IOException e) {
                e.printStackTrace();
            }

            return cipher;
        }

        @Override
        public Codec encrypt(Integer field) {
            efields.add(Integer.valueOf(field));
            return this;
        }

        @Override
        public Codec addHash(Integer field) {
            hfields.add(Integer.valueOf(field));
            return this;
        }

        @Override
        public Codec encrytWithHash(Integer field) {
            return encrypt(field).addHash(field);
        }

        @Override
        public Codec setCode(String code) {
            this.code = code;
            return this;
        }
    }

    @Test
    public void csvplaytemp(){
        String data = "Rajeev Kumar Singh,\"rajeevs@example.com\",+91-9999999999,India\n" +
                "Sachin Tendulkar,sachin@example.com,+91-9999999998,India\n" +
                "Barak Obama,barak.obama@example.com,+1-1111111111,United States\n" +
                "Donald Trump,donald.trump@example.com,+1-2222222222,United States";

        CSVParser csvParser = null;
        StringWriter csvInString = new StringWriter();
        CSVPrinter writer = null;

        try {
            csvParser = CSVParser.parse(data, CSVFormat.DEFAULT.withSkipHeaderRecord());
            writer = new CSVPrinter(csvInString, CSVFormat.DEFAULT.withSkipHeaderRecord());
            for (CSVRecord csvRecord : csvParser) {
                List<String> list = new LinkedList<>();
                for(String field : csvRecord){
                    list.add(field);
                }

                list.add("DEK");
                list.add("KEKId");
                list.add("Code-Type");
                writer.printRecord(list);
            }

            writer.close(true);
            System.out.println(csvInString);
            System.out.println(data);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
