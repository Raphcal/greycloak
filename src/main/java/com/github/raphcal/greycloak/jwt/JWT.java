package com.github.raphcal.greycloak.jwt;

import com.google.gson.Gson;
import com.google.gson.stream.JsonReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import java.util.Date;
import java.util.regex.Pattern;

/**
 * Jeton d'identification WEB JSON.
 *
 * @author Raphaël Calabro (ddaeke-github at yahoo.fr)
 */
public class JWT {
    public static JWT fromJson(String json) throws IOException {
        final String[] parts = json.split(Pattern.quote("."));
        if (parts.length != 3) {
            return null;
        }
        final Base64.Decoder decoder = Base64.getUrlDecoder();
        final JWT jwt = new JWT();
        jwt.header = decodePart(parts[0], JWTHeader.class);
        jwt.payload = decodePart(parts[1], JWTPayload.class);
        jwt.signature = decoder.decode(parts[2]);
        return jwt;
    }

    private static String encodePart(Object part) {
        final Gson gson = new Gson();
        final Base64.Encoder encoder = Base64.getUrlEncoder();
        return encoder.encodeToString(gson.toJson(part).getBytes(StandardCharsets.UTF_8)).replace("=", "");
    }

    private static <T> T decodePart(String part, Class<T> clazz) throws IOException {
        final Gson gson = new Gson();
        final Base64.Decoder decoder = Base64.getUrlDecoder();

        final String value;
        switch (part.length() % 4) {
            case 2:
                value = part + "==";
                break;
            case 3:
                value = part + "=";
                break;
            default:
                value = part;
                break;
        }

        try (JsonReader reader = new JsonReader(new InputStreamReader(new ByteArrayInputStream(decoder.decode(value)), StandardCharsets.UTF_8))) {
            return gson.fromJson(reader, clazz);
        }
    }

    private JWTHeader header;
    private JWTPayload payload;
    private byte[] signature;

    public JWT() {
        // Vide.
    }

    public JWT(JWTHeader header, JWTPayload payload) {
        this.header = header;
        this.payload = payload;
    }

    public JWTHeader getHeader() {
        return header;
    }

    public JWTPayload getPayload() {
        return payload;
    }

    public void signUsing(PrivateKey key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        final Signature rsaSignature = Signature.getInstance("SHA256withRSA");
        rsaSignature.initSign(key);
        rsaSignature.update((encodePart(header) + '.' + encodePart(payload)).getBytes(StandardCharsets.UTF_8));
        this.signature = rsaSignature.sign();
    }

    public boolean isSignatureValid(PublicKey key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        final Signature rsaSignature = Signature.getInstance("SHA256withRSA");
        rsaSignature.initVerify(key);
        rsaSignature.update((encodePart(header) + '.' + encodePart(payload)).getBytes(StandardCharsets.UTF_8));
        return rsaSignature.verify(signature);
    }

    public String toJson() {
        return encodePart(header) + '.' + encodePart(payload) + '.' + Base64.getUrlEncoder().encodeToString(signature).replace("=", "");
    }

    public boolean hasExpired() {
        return (new Date().getTime() / 1000) > payload.getExpiration();
    }

}
