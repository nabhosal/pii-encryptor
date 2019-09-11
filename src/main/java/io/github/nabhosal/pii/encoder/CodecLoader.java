package io.github.nabhosal.pii.encoder;
/**
 * <h1>CodecLoader</h1>
 * Interface provide ability to load Codec from external sources such file, databases, or through codec defined in
 * java class e.g. StubCodecLoader
 * <p>
 *
 * @author  Nilesh Bhosale
 * @since   2019-09-06
 */
public interface CodecLoader {
    /**
     * The loadByCode method provide usable api to load codec in PIIHandler instance
     *
     * @param code is unique identifier for Codec
     * @return Codec
     */
    public Codec loadByCode(String code);

    public String infer(String cipher);
}
