package com.github.raphcal.greycloak;

import com.google.gson.annotations.SerializedName;

/**
 * En-tête du jeton JSON Web.
 *
 * @author Raphaël Calabro (ddaeke-github at yahoo.fr)
 */
public class JWTHeader {

    /**
     * Algorithme utilisé pour la signature.
     */
    @SerializedName("alg")
    private String algorithm;

    /**
     * Type de jeton.
     */
    @SerializedName("typ")
    private String tokenType;

    /**
     * Identifiant de la clef utilisée pour la signature.
     */
    @SerializedName("kid")
    private String keyIdentifier;

    public JWTHeader() {
        // Vide.
    }

    public JWTHeader(String algorithm, String tokenType, String keyIdentifier) {
        this.algorithm = algorithm;
        this.tokenType = tokenType;
        this.keyIdentifier = keyIdentifier;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public String getKeyIdentifier() {
        return keyIdentifier;
    }

    public void setKeyIdentifier(String keyIdentifier) {
        this.keyIdentifier = keyIdentifier;
    }
}
