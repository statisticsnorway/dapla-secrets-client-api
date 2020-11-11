package no.ssb.dapla.secrets.api;

import no.ssb.service.provider.api.ProviderConfigurator;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;

/**
 * SecretManagerClient is a provider based API for reading secrets.
 */
public interface SecretManagerClient extends AutoCloseable {

    /**
     * Read secret
     *
     * @param secretName
     * @return secret value as string
     */
    String readString(String secretName);

    /**
     * Read secret for a specific version
     *
     * @param secretName
     * @param secretVersion
     * @return secret value as string
     */
    String readString(String secretName, String secretVersion);

    /**
     * Read secret
     *
     * @param secretName
     * @return secret value as byte-array
     */
    byte[] readBytes(String secretName);

    /**
     * Read secret for a specific version
     *
     * @param secretName
     * @param secretVersion
     * @return secret value as byte-array
     */
    byte[] readBytes(String secretName, String secretVersion);

    /**
     * Close provider
     */
    @Override
    void close();

    /**
     * Convenience method that converts byte-array to char-array as UTF-8.
     *
     * Please notice: The input byte-array will be cleared after conversion.
     *
     * @param bytes input buffer
     * @return characters array as utf8. Return an empty char-array if input is null or empty
     *         the user is responsible for clearing a char-array copy.
     */
    static char[] safeCharArrayAsUTF8(final byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return new char[0];
        }
        CharBuffer cb = StandardCharsets.UTF_8.decode(ByteBuffer.wrap(bytes));
        final char[] chars = new char[cb.remaining()];
        cb.get(chars);
        Arrays.fill(bytes, (byte) 0);
        cb.clear();
        return chars;
    }

    /**
     * Create SecretManagerClient for a 'secrets.provider'
     *
     * @param configuration Each provider requires their own properties
     * @return SecretManagerClient instance
     */
    static SecretManagerClient create(Map<String, String> configuration) {
        return ProviderConfigurator.configure(configuration, configuration.get("secrets.provider"), SecretManagerClientInitializer.class);
    }

}
