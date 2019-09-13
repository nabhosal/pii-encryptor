package io.github.nabhosal.pii.util;

import java.io.*;

public class Utils {

    public static ConfigLoaderUtil CONFIG = new ConfigLoaderUtil();

    public static class ConfigLoaderUtil{

        public InputStream getConfigStream(String resourceLocation, String key_file, String default_key_files) throws FileNotFoundException {
            ClassLoader ctxClsLoader = Thread.currentThread().getContextClassLoader();
            InputStream is = null;
            if (ctxClsLoader != null) {
                is = ctxClsLoader.getResourceAsStream(resourceLocation);
            }

            if (is == null && !resourceLocation.equals(key_file)) {
                is = new FileInputStream(resourceLocation);
            } else if (is == null && resourceLocation.equals(key_file)) {
                is = getClass().getClassLoader().getResourceAsStream(resourceLocation);
                if (is == null) {
                    is = getClass().getClassLoader().getResourceAsStream(default_key_files);
                }
            }
            return is;
        }

        public String loadProperties(String resourceLocation, String key_file, String default_key_files) {
            try {

                BufferedReader reader = new BufferedReader(new InputStreamReader(new BufferedInputStream(getConfigStream(resourceLocation, key_file, default_key_files))));

                String line;
                StringBuilder sb = new StringBuilder();
                while ((line = reader.readLine()) != null) {
                    sb.append(line);
                }
                reader.close();

                return sb.toString();
            } catch (FileNotFoundException e) {
            } catch (IOException e) {
            }
            return "";
        }
    }

}
