# PII Encryptor 

It is a utility project to help implement field-level encryption on the csv or json document. It is designed to be used by service which needs PCI or similar compliance. It preloaded with a default implementation for csv and json, it simplifies indicating fields using Jsonpath for json and field index in case of csv. 
Preloaded class are designed to take care of most common implementation challenges, making developer focus on encryption strategy.  

##### Get it as Maven dependency
```xml
<dependency>
  <groupId>io.github.nabhosal</groupId>
  <artifactId>app-security</artifactId>
  <version>1.0-SNAPSHOT</version>
</dependency>
```
external dependencies it used (All are authentic & secure libraries)
```groovy
    compile group: 'com.fasterxml.jackson.core', name: 'jackson-databind', version: '2.9.9'
    compile group: 'com.fasterxml.jackson.core', name: 'jackson-core', version: '2.9.9'
    compile group: 'com.jayway.jsonpath', name: 'json-path', version: '2.4.0'
    compile group: 'commons-codec', name: 'commons-codec', version: '1.13'
    compile group: 'org.apache.commons', name: 'commons-csv', version: '1.7'
```

### Basic terminologies
 
* **Field-level encryption:** focus on encrypting data at specified fields only.
* **Data encryption key (DEK):** is an encryption key whose function it is to encrypt and decrypt the data.
* **Key encryption key (KEK):** is an encryption key whose function it is to encrypt and decrypt the DEK.
* **Encrypted data encryption key (eDEK):** a shareable DEK encrypted using KEK
* **Key Management System (KMS):** is the system that houses the key management
#### Implementation terminologies
* **Codec:** a metadata detecting the strategy usable for encrypting or hashing a given fields
* **CodecLoader:** codec provider from external sources such as db, or through java class
* **EncryptionService:** a AES-256 based encryption service for encrypting & decrypting the data, 
it relies on creating new encryption session for encrypting and rebuilding the encryption session while decrypting.
* **Key Provider:** KEK key list provider from external sources such as db, files, or KMS

### Implementation philosophy
1. Encrypted data is self sufficient, it know what strategy(i.e. codec) & data key (i.e. eDEK) is used to encrypt. 
Since eDEK is in encrypted using different key (i.e KEK), the data contains reference to KEK.
2. If DEK in single document is compromised, it wont have affect on other document since the DEK are fairly unique to each document
3. if KEK is compromised, it will compromise only documents where given KEK is being used, **_Key provider_** provide strategy strong 
enough to distribute KEK across multiple document to handle incident of KEK compromises.

### Example
Sample input json containing PII data. 

the fields for encryption is `_pan, mobile, arrays[0].k2, arrays[1].k2_`

the fields for hashing is `_pan_name, nested.key1, mobile, arrays[0].k1_`
```json5
{
    "name":"full name",
    "pan":"123124324",
    "pan_name":"pan full name",
    "mobile":"4534534534",
    "nested":{
        "key1":"value1",
        "key2":"value2"
    },
    "arrays":[
        {
            "k1":"v1",
            "k2":"v2"
        },
        {
            "k1":"v11",
            "k2":"v21"
        }
    ]
}
```
#### field-level encrypted data

for every hash field, a surrogate new field is added starting with `h_` 

the encrypted document contains metadata such as _`codec, DEK, KEKID`_. 

```json5
{
    "name":"full name",
    "pan":"H+msxmkCaSvTFLTIYZDTUw==",
    "pan_name":"pan full name",
    "mobile":"5Hp8tjD10rdwlJrMoM1qCw==",
    "nested":{
        "key1":"value1",
        "key2":"value2",
        "h_key1":"3c9683017f9e4bf33d0fbedd26bf143fd72de9b9dd145441b75f0604047ea28e"
    },
    "arrays":[
        {
            "k1":"v1",
            "k2":"QcuAVmE/hvy4zQG/Vg7VNg==",
            "h_k1":"3bfc269594ef649228e9a74bab00f042efc91d5acc6fbee31a382e80d42388fe"
        },
        {
            "k1":"v11",
            "k2":"UwGk6VAHJl8dZDVKMpeUAw=="
        }
    ],
    "h_pan_name":"8766d7e0b05c3fd0e62307e4a4551999a8308d411b24b8539afea0a4e42ab006",
    "h_mobile":"ccbf71ae2de17bcea3950fdd0b0cd2f47b6901f7244267324088d7f914c068c5",
    "codec":"test-code-imp",
    "DEK":"2/vGlA+G+hgFMzAWvlJOZiwoQMWXyHnjL3Faeop5Xt4=",
    "KEKID":"1d3ca4c3-44bc-4c61-944c-f82b591787fa"
}
```

### How to use API
the standard method will return PIIHandler with default json implementation  _`JsonBasedStandardCodec`_ for json codec, _`DemoJsonCodecLoader`_ for codecloader, _`MapBasedKeyProviderImpl`_ for keyProvider.
```java
                PIIHandler piiHandler = PIIHandlerBuilder.standard();
                String encrypteddata = piiHandler.apply(input_json, "test-code-imp");
                String decrypteddata = piiHandler.resolve(encrypteddata);
        
                System.out.println("orginaldata "+input_json);
                System.out.println("encrypteddata "+encrypteddata);
                System.out.println("orginaldata "+input_json);
            
```
#### JsonBasedStandardCodec used in example
```java
        JsonBasedStandardCodec codec = new JsonBasedStandardCodec();
        codec.encrypt("$.pan");
        codec.addHash("$.pan_name");
        codec.addHash("$.nested.key1");
        codec.encrytWithHash("$.mobile");
        codec.addHash("$.arrays[0].k1");
        codec.encrypt("$.arrays[*].k2");
        codec.setCode("test-code-imp");
        codec.setCodecType(DEFAULT_CODECTYPE);
```
#### Result
```commandline
orginaldata {"name":"full name","pan":"123124324","pan_name":"pan full name","mobile":"4534534534","hello":"Hash","nested":{"key1":"value1","key2":"value2"},"arrays":[{"k1":"v1","k2":"v2"},{"k1":"v11","k2":"v21"}]}
encrypteddata {"name":"full name","pan":"kPNOioYbrsw/64s0df4n+A==","pan_name":"pan full name","mobile":"WuEsq5E6a9SW/V4kyNRI5A==","hello":"Hash","nested":{"key1":"value1","key2":"value2","h_key1":"3c9683017f9e4bf33d0fbedd26bf143fd72de9b9dd145441b75f0604047ea28e"},"arrays":[{"k1":"v1","k2":"69jco+QP0+hmJNsmGhCThg==","h_k1":"3bfc269594ef649228e9a74bab00f042efc91d5acc6fbee31a382e80d42388fe"},{"k1":"v11","k2":"/u/Wb9ZKgjav6dv9Qmz4uw=="}],"h_pan_name":"8766d7e0b05c3fd0e62307e4a4551999a8308d411b24b8539afea0a4e42ab006","h_mobile":"ccbf71ae2de17bcea3950fdd0b0cd2f47b6901f7244267324088d7f914c068c5","codec":"test-code-imp","DEK":"mOoWkgCO58yXFbK1E6Llu0iuiX/g8mU/bJscH+bldLQ=","KEKID":"0d50f9aa-6436-4cdd-b88d-a23d8cdd90b7"}
decrypteddata {"name":"full name","pan":"123124324","pan_name":"pan full name","mobile":"4534534534","hello":"Hash","nested":{"key1":"value1","key2":"value2"},"arrays":[{"k1":"v1","k2":"v2"},{"k1":"v11","k2":"v21"}]}

```

#### How to apply field-level encryption on CSV
```java
/* csv data */
private static String input_csv = "Rajeev Kumar Singh,\"rajeevs@example.com\",+91-9999999999,India\n" +
            "Sachin Tendulkar,sachin@example.com,+91-9999999998,India\n" +
            "Barak Obama,barak.obama@example.com,+1-1111111111,United States\n" +
            "Donald Trump,donald.trump@example.com,+1-2222222222,United States";

/* Codec */
CSVByFieldIndexStandardCodec c1 = new CSVByFieldIndexStandardCodec();
            c1.addHash(2);
            c1.encrypt(0);
            c1.setCode("test-01");
            
/* Encrypt & decrypt the csv field level data */

 PIIHandler piiHandler = PIIHandlerBuilder.withDefault()
                .withCodecLoader(new DemoCSVCodecLoader()).build();
        String encrypteddata = piiHandler.apply(input_csv, "test-01");
        String decrypteddata = piiHandler.resolve(encrypteddata);
        assertNotEquals("input csv is not same after decryption", decrypteddata, input_csv);

/* for more details refer TestCSVCodec.java */
```

#### Working with custom implementation

<details><summary>Custom implementation to handle CSV </summary>
<p>

```java
package io.github.nabhosal.pii.test;

import io.github.nabhosal.pii.PIIHandler;
import io.github.nabhosal.pii.PIIHandlerBuilder;
import io.github.nabhosal.pii.cipher.EncryptionService;
import io.github.nabhosal.pii.encoder.Codec;
import io.github.nabhosal.pii.encoder.CodecLoader;
import io.github.nabhosal.pii.encoder.impl.DemoCSVCodecLoader;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVPrinter;
import org.apache.commons.csv.CSVRecord;
import org.junit.Test;

import java.io.IOException;
import java.io.StringWriter;
import java.util.*;

import static org.junit.Assert.assertNotEquals;

public class TestCSVCodec {

    private static String input_csv = "Rajeev Kumar Singh,\"rajeevs@example.com\",+91-9999999999,India\n" +
            "Sachin Tendulkar,sachin@example.com,+91-9999999998,India\n" +
            "Barak Obama,barak.obama@example.com,+1-1111111111,United States\n" +
            "Donald Trump,donald.trump@example.com,+1-2222222222,United States";

    
    @Test
    public void testCustomCSVbyFieldImpl(){
        PIIHandler piiHandler = PIIHandlerBuilder.withDefault().withCodecLoader(new CSVByFieldIndexCodecLoader()).build();
        String encrypteddata = piiHandler.apply(input_csv, "test-01");
        String decrypteddata = piiHandler.resolve(encrypteddata);
        assertNotEquals("input csv is not same after decryption", decrypteddata, input_csv);
    }

    static class CSVByFieldIndexCodecLoader implements CodecLoader {

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

}
```
</p>
</details>

<details><summary>Building PIIHandler with custom CodecLoader & EncryptionService </summary>
<p>

```java
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


```
</p>
</details>


