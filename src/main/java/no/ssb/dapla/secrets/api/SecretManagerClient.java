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
     * Add a binary version of the secret.
     *
     * @param secretName  the name of the secret to add a version to.
     * @param secretValue the value of the secret version.
     * @return the version name
     */
    String addVersion(String secretName, byte[] secretValue);

    /**
     * Add a string version of the secret.
     *
     * @param secretName  the name of the secret to add a version to.
     * @param secretValue the value of the secret version.
     * @return the version name
     */
    default String addVersion(String secretName, String secretValue) {
        return addVersion(secretName, secretValue.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Read secret
     *
     * @param secretName
     * @return secret value as string
     */
    default String readString(String secretName) {
        return new String(readBytes(secretName), StandardCharsets.UTF_8);
    }

    /**
     * Read secret for a specific version
     *
     * @param secretName
     * @param secretVersion
     * @return secret value as string
     */
    default String readString(String secretName, String secretVersion) {
        return new String(readBytes(secretName, secretVersion), StandardCharsets.UTF_8);
    }

    /**
     * Read secret
     *
     * @param secretName
     * @return secret value as byte-array
     */
    default byte[] readBytes(String secretName) {
        return readBytes(secretName, null);
    }

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
     * <p>
     * Please notice: The input byte-array will be cleared after conversion.
     *
     * @param bytes input buffer
     * @return a char buffer as utf8. If the input is null or empty, an empty char-array is returned.
     * the user is responsible for clearing a char-array copy.
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
