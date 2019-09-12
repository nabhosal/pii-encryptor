package io.github.nabhosal.pii.encoder.impl;

import io.github.nabhosal.pii.encoder.Codec;
import io.github.nabhosal.pii.encoder.CodecLoader;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;

import java.io.IOException;
import java.util.HashMap;
import java.util.Objects;

public class DemoCSVCodecLoader implements CodecLoader {

    private final HashMap<String, Codec> codecMap = new HashMap<>();
    private CSVFormat csvFormat;

    public DemoCSVCodecLoader(CSVFormat csvFormat){
        this();
        Objects.requireNonNull(csvFormat, "CSV Format cannot be null");
        this.csvFormat = csvFormat;
    }

    public DemoCSVCodecLoader(){
        CSVByFieldIndexCodec c1 = new CSVByFieldIndexCodec();
        c1.addHash(2);
        c1.encrypt(0);
        c1.setCode("test-01");

        codecMap.put(c1.getCode(), c1);
        csvFormat = CSVFormat.DEFAULT.withSkipHeaderRecord();
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
