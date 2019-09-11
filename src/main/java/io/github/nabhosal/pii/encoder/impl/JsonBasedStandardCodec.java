package io.github.nabhosal.pii.encoder.impl;

import com.jayway.jsonpath.*;
import io.github.nabhosal.pii.cipher.EncryptionService;
import io.github.nabhosal.pii.encoder.Codec;
import com.jayway.jsonpath.spi.json.JacksonJsonNodeJsonProvider;
import com.jayway.jsonpath.spi.mapper.JacksonMappingProvider;
import org.apache.commons.codec.digest.DigestUtils;

import java.util.LinkedList;
import java.util.List;

public class JsonBasedStandardCodec implements Codec<String> {

    private String code;
    private String codecType;
    public static final String DEFAULT_CODECTYPE = "json-standard-codec-01";
    private List<Operation> operationList;

    public Codec setCode(String code) {
        this.code = code;
        return this;
    }

    public String getCodecType() {
        return codecType;
    }

    public void setCodecType(String codecType) {
        this.codecType = codecType;
    }

    public List<Operation> getOperationList() {
        return operationList;
    }

    public void setOperationList(List<Operation> operationList) {
        this.operationList = operationList;
    }

    public JsonBasedStandardCodec(){
        operationList = new LinkedList<>();
    }

    private JsonBasedStandardCodec addOperation(String jsonPath, boolean isEncrypt, boolean isHash){
        operationList.add(new Operation(jsonPath, isEncrypt, isHash));
        return this;
    }

    @Override
    public Codec encrypt(String jsonPath){
        operationList.add(new Operation(jsonPath, true, false));
        return this;
    }

    @Override
    public Codec addHash(String jsonPath){
        operationList.add(new Operation(jsonPath, false, true));
        return this;
    }

    @Override
    public Codec encrytWithHash(String jsonPath){
        operationList.add(new Operation(jsonPath, true, true));
        return this;
    }

    @Override
    public String getCode() {
        return this.code;
    }

    static class Operation{

        private String jsonPath;
        private boolean isEncrypt;
        private boolean isHash;

        public Operation(String jsonPath, boolean isEncrypt, boolean isHash){
            this.jsonPath = jsonPath;
            this.isEncrypt = isEncrypt;
            this.isHash = isHash;
        }

        @Override
        public String toString() {
            return "Operation{" +
                    "jsonPath='" + jsonPath + '\'' +
                    ", isEncrypt=" + isEncrypt +
                    ", isHash=" + isHash +
                    '}';
        }
    }

    @Override
    public String toString() {
        return "JsonBasedStandardCodec{" +
                "code='" + code + '\'' +
                ", codecType='" + codecType + '\'' +
                ", operationList=" + operationList +
                '}';
    }

    private static final Configuration configuration_for_path = Configuration.builder()
            .jsonProvider(new JacksonJsonNodeJsonProvider())
            .mappingProvider(new JacksonMappingProvider())
            .options(Option.ALWAYS_RETURN_LIST, Option.AS_PATH_LIST)
            .build();

    private static final Configuration configuration = Configuration.builder()
            .jsonProvider(new JacksonJsonNodeJsonProvider())
            .mappingProvider(new JacksonMappingProvider())
            .build();

    @Override
    public String apply(String json, EncryptionService service){

        DocumentContext jsonDoc = JsonPath.using(configuration_for_path).parse(json);
        DocumentContext jsonDocRead = JsonPath.using(configuration).parse(json);

        EncryptionService.EncryptionSession session = service.newSession();

        for(Operation o : operationList){
            List<String> valuePaths = jsonDoc.read(o.jsonPath, List.class);

            if(o.isHash){
                for(String jpath : valuePaths){

                    String value_raw = jsonDocRead.read(jpath).toString();
                    String value = value_raw.substring(1, value_raw.length() - 1);
                    String parentNode = jpath.substring(0, jpath.lastIndexOf('['));
                    String key_raw = "h_"+jpath.substring(jpath.lastIndexOf('[') + 1);
                    String key = key_raw.substring(0, key_raw.length() - 2).replaceAll("'","");
                    String hashvalue = DigestUtils.sha256Hex(value);
                    jsonDoc.put(parentNode, key, hashvalue);
                }

            }
            if(o.isEncrypt){
                for(String jpath : valuePaths){
                    String value_raw = jsonDocRead.read(jpath).toString();
                    String value = value_raw.substring(1, value_raw.length() - 1);
                    jsonDoc.set(jpath, service.encrypt(session, value));
                }

            }
        }

        jsonDoc.put("$", "codec", getCode());
        jsonDoc.put("$", "DEK", session.geteDEK());
        jsonDoc.put("$", "KEKID", session.getKEKId());

        return jsonDoc.jsonString();
    }

    @Override
    public String resolve(String json, EncryptionService service) {

        DocumentContext jsonDoc = JsonPath.using(configuration_for_path).parse(json);
        DocumentContext jsonDocRead = JsonPath.using(configuration).parse(json);
        String eDEKraw = "";
        String KEKIdraw = "";
        try{
            eDEKraw = jsonDocRead.read("$.DEK").toString();
            KEKIdraw = jsonDocRead.read("$.KEKID").toString();
        }catch (PathNotFoundException e){
            System.out.println("JsonBasedStandardCodec: either DEK or KEKID is absent");
            return json;
        }

        String eDEK = eDEKraw.substring(1, eDEKraw.length() - 1);
        String KEKId = KEKIdraw.substring(1, KEKIdraw.length() - 1);

        EncryptionService.EncryptionSession session = service.buildSession(eDEK, KEKId);

        for(Operation o : operationList){
            List<String> valuePaths = jsonDoc.read(o.jsonPath, List.class);
            if(o.isHash){
                for(String jpath : valuePaths){
                    String parentNode = jpath.substring(0, jpath.lastIndexOf('['));
                    String key_raw = "h_"+jpath.substring(jpath.lastIndexOf('[') + 1);
                    String key = key_raw.substring(0, key_raw.length() - 2).replaceAll("'","");
                    String delete_hash_key = parentNode+"['"+key+"']";
                    jsonDoc.delete(delete_hash_key);
                }

            }
            if(o.isEncrypt){
                for(String jpath : valuePaths){
                    String value_raw = jsonDocRead.read(jpath).toString();
                    String value = value_raw.substring(1, value_raw.length() - 1);
                    jsonDoc.set(jpath, service.decrypt(session, value));
                }

            }
        }

        jsonDoc.delete("$.codec");
        jsonDoc.delete("$.DEK");
        jsonDoc.delete("$.KEKID");

        return jsonDoc.jsonString();
    }

}
