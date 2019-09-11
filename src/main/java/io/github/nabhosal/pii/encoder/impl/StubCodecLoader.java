package io.github.nabhosal.pii.encoder.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.nabhosal.pii.encoder.Codec;
import io.github.nabhosal.pii.encoder.CodecLoader;

import java.io.IOException;
import java.util.HashMap;

import static io.github.nabhosal.pii.encoder.impl.JsonBasedStandardCodec.DEFAULT_CODECTYPE;

public class StubCodecLoader implements CodecLoader {

    private HashMap<String, Codec> codeMap = new HashMap<>();
    private final static ObjectMapper objectMapper = new ObjectMapper();

    private Codec getDefault(){
        JsonBasedStandardCodec codec = new JsonBasedStandardCodec();
        codec.encrypt("$.pan");
        codec.encrytWithHash("$.mobile");
        codec.setCode("default");
        codec.setCodecType(DEFAULT_CODECTYPE);
        return codec;
    }

    public StubCodecLoader(){
        JsonBasedStandardCodec codec = new JsonBasedStandardCodec();
        codec.encrypt("$.pan");
        codec.addHash("$.pan_name");
        codec.encrytWithHash("$.mobile");
        codec.setCode("test-code");
        codec.setCodecType(DEFAULT_CODECTYPE);

        JsonBasedStandardCodec codec1 = new JsonBasedStandardCodec();
        codec1.encrypt("$.pan");
        codec1.encrytWithHash("$.mobile");
        codec1.setCode("test-code-two");
        codec1.setCodecType(DEFAULT_CODECTYPE);

        JsonBasedStandardCodec codec2 = new JsonBasedStandardCodec();
        codec2.encrypt("$.pan");
        codec2.addHash("$.pan_name");
        codec2.addHash("$.nested.key1");
        codec2.encrytWithHash("$.mobile");
        codec2.addHash("$.arrays[0].k1");
        codec2.encrypt("$.arrays[*].k2");
        codec2.setCode("test-code-imp");
        codec2.setCodecType(DEFAULT_CODECTYPE);

        codeMap.put(codec.getCode(), codec);
        codeMap.put(codec1.getCode(), codec1);
        codeMap.put(codec2.getCode(), codec2);
    }

    @Override
    public Codec loadByCode(String code){

        return codeMap.getOrDefault(code, getDefault());
    }

    @Override
    public String infer(String cipher) {
        String codecStr = "";
        try {
            codecStr = objectMapper.readTree(cipher).get("codec").asText("");
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
