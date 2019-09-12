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
    public void testCSVByField(){
        PIIHandler piiHandler = PIIHandlerBuilder.withDefault()
                .withCodecLoader(new DemoCSVCodecLoader()).build();
        String encrypteddata = piiHandler.apply(input_csv, "test-01");
        String decrypteddata = piiHandler.resolve(encrypteddata);
        assertNotEquals("input csv is not same after decryption", decrypteddata, input_csv);
    }

    @Test
    public void testCSVByFieldPassCustomCSVFormat(){
        PIIHandler piiHandler = PIIHandlerBuilder.withDefault()
                .withCodecLoader(new DemoCSVCodecLoader(CSVFormat.DEFAULT.withSkipHeaderRecord()))
                .build();
        String encrypteddata = piiHandler.apply(input_csv, "test-01");
        String decrypteddata = piiHandler.resolve(encrypteddata);
        assertNotEquals("input csv is not same after decryption", decrypteddata, input_csv);
    }

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
