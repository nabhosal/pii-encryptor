package io.github.nabhosal.pii.encoder.impl;

import io.github.nabhosal.pii.cipher.EncryptionService;
import io.github.nabhosal.pii.encoder.Codec;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVPrinter;
import org.apache.commons.csv.CSVRecord;

import java.io.IOException;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class CSVByFieldIndexCodec implements Codec<Integer>{

    private String code;
    private String codecType;
    public static final String DEFAULT_CODECTYPE = "csv_byindex_01";
    private Set<Integer> efields;
    private Set<Integer> hfields;
    private CSVFormat csvFormat;

    public CSVByFieldIndexCodec(){
        efields = new LinkedHashSet<>();
        hfields = new LinkedHashSet<>();
        csvFormat = CSVFormat.DEFAULT.withSkipHeaderRecord();
    }

    public CSVByFieldIndexCodec(CSVFormat csvFormat){
        efields = new LinkedHashSet<>();
        hfields = new LinkedHashSet<>();
        this.csvFormat = csvFormat;
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
            csvParser = CSVParser.parse(rawdata, csvFormat);
            writer = new CSVPrinter(csvInString, csvFormat);
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
            csvParser = CSVParser.parse(cipher, csvFormat);
            writer = new CSVPrinter(csvInString, csvFormat);

            CSVParser forInfer = CSVParser.parse(cipher, csvFormat);
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
