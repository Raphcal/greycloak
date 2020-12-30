package com.github.raphcal.greycloak;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;

/**
 *
 * @author Raphaël Calabro (raphael.calabro.external2@banque-france.fr)
 */
public class Session {
    private final String realm;
    private final String id = UUID.randomUUID().toString();
    private final List<String> codes = new ArrayList<>();
    private final List<String> validRefreshTokens = new ArrayList<>();
    private String nonce;

    public Session(String realm) {
        this.realm = realm;
    }

    public String getRealm() {
        return realm;
    }

    public String getId() {
        return id;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String generateCode() {
        final String code = UUID.randomUUID().toString();
        codes.add(code);
        return code;
    }

    public boolean isCodeValid(String code) {
        return codes.remove(code);
    }

    public void addRefreshToken(String refreshToken) {
        validRefreshTokens.add(refreshToken);
    }

    public boolean isRefreshTokenValid(String refreshToken) throws IOException {
        if (refreshToken == null) {
            return false;
        }
        final Iterator<String> iterator = validRefreshTokens.iterator();
        while (iterator.hasNext()) {
            final String validRefreshToken = iterator.next();
            final JWT token = JWT.fromJson(validRefreshToken);
            if (token.hasExpired()) {
                iterator.remove();
            } else if (validRefreshToken.equals(refreshToken)) {
                return true;
            }
        }
        return false;
    }
}
