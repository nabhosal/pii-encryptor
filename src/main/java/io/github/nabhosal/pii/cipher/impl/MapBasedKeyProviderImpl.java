package io.github.nabhosal.pii.cipher.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.nabhosal.pii.cipher.KeyProvider;
import io.github.nabhosal.pii.util.Utils;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

public class MapBasedKeyProviderImpl implements KeyProvider {

    private final Map<String, String> KEKMap;
    private static final String DEFAULT_KEK_FILE = "KEKkeys.json";
    private static final String SYS_KEK_KEYS_PATH = "kek-keys-path";

    public MapBasedKeyProviderImpl(){

        KEKMap = new HashMap<>();
        ObjectMapper mapper = new ObjectMapper();
        String resourceLocation = System.getProperty(SYS_KEK_KEYS_PATH, DEFAULT_KEK_FILE);
        String keyFileContent = Utils.get().loadProperties(resourceLocation, DEFAULT_KEK_FILE, DEFAULT_KEK_FILE);

        if ("".equalsIgnoreCase(keyFileContent)){
            throw new RuntimeException("Not able to load KEK keys from "+resourceLocation);
        }

        try {
            Map<String, Object>kekkeymap = mapper.readValue(keyFileContent, Map.class);
            for (Map.Entry<String, Object> entry : kekkeymap.entrySet()){
                KEKMap.put(entry.getKey(), ((Map<String, String>)entry.getValue()).get("kek"));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        validateKeyMap();
    }

    @Override
    public String getKeyById(String id) {
        return KEKMap.get(id);
    }

    @Override
    public String getKeyForEncryption(Map<String, Object> params) {
        return (String)KEKMap.keySet().toArray()[new Random(LocalDateTime.now().getNano()).nextInt(KEKMap.keySet().toArray().length)];
    }

    private void validateKeyMap(){
        if (KEKMap.isEmpty()){
            throw new RuntimeException("KEK keyset is empty");
        }
    }

}
