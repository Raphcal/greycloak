package com.github.raphcal.greycloak.jwt;

import com.google.gson.annotations.SerializedName;
import java.util.Map;

/**
 * Contenu du JWT.
 *
 * @author Raphaël Calabro (raphael.calabro.external2@banque-france.fr)
 */
public class JWTPayload {

    public static final String REALM_ACCESS_ROLES = "roles";

    /**
     * Identifiant unique du jeton.
     */
    @SerializedName("jti")
    private String jwtIdentifier;

    /**
     * Heure à laquelle ce jeton expire.
     */
    @SerializedName("exp")
    private long expiration;

    /**
     * Heure à partir de laquelle ce jeton peut être utilisé.
     */
    @SerializedName("nbf")
    private long notValidBefore;

    /**
     * Heure de création du jeton.
     */
    @SerializedName("iat")
    private long issuedAt;

    /**
     * Auteur du jeton (généralement l'adresse de Keycloak).
     */
    @SerializedName("iss")
    private String issuer;

    /**
     * Destinataire du jeton.
     */
    @SerializedName("aud")
    private String audience;

    /**
     * Identifiant de l'utilisateur.
     */
    @SerializedName("sub")
    private String subject;

    /**
     * Type du jeton.
     * <code>ID</code> pour un refresh token, <code>Bearer</code> pour un jeton
     * d'accès.
     */
    @SerializedName("typ")
    private String type;

    /**
     * Site qui a le droit d'utiliser ce jeton.
     */
    @SerializedName("azp")
    private String authorizedParty;

    /**
     * Horaire de connexion.
     */
    @SerializedName("auth_time")
    private long authorizedTime;

    @SerializedName("session_state")
    private String sessionState;

    /**
     * Vaut <code>1</code>.
     */
    @SerializedName("acr")
    private String authorizationContextClass;

    /**
     * Liste des URLs autorisés à utiliser ce jeton.
     * Champ du jeton d'accès.
     */
    @SerializedName("allowed-origins")
    private String[] allowedOrigins;

    /**
     * Droits d'accès.
     * Champ du jeton d'accès.
     */
    @SerializedName("realm_access")
    private Map<String, Object> realmAccess;

    /**
     * Droits d'accès aux ressources de Keycloak.
     * Champ du jeton d'accès.
     */
    @SerializedName("resource_access")
    private Map<String, Object> resourceAccess;

    /**
     * Champ du jeton d'accès.
     * Vaut <code>openid profile email</code>.
     */
    private String scope;

    /**
     * Identifiant unique partagé entre le client originaire de la demande de
     * connexion et le serveur afin d'éviter le partage de jeton.
     */
    private String nonce;

    /**
     * Indique si l'utilisateur a vérifié son adresse e-mail.
     */
    @SerializedName("email_verified")
    private Boolean emailVerified;

    /**
     * Nom complet de la personne connectée.
     */
    private String name;

    /**
     * Nom d'utilisateur.
     */
    private String username;

    /**
     * Login de l'utilisateur.
     */
    @SerializedName("preferred_username")
    private String preferredUsername;

    /**
     * Prénom de l'utilisateur.
     */
    @SerializedName("given_name")
    private String givenName;

    /**
     * Nom de famille.
     */
    @SerializedName("family_name")
    private String familyName;

    public String getJwtIdentifier() {
        return jwtIdentifier;
    }

    public void setJwtIdentifier(String jwtIdentifier) {
        this.jwtIdentifier = jwtIdentifier;
    }

    public long getExpiration() {
        return expiration;
    }

    public void setExpiration(long expiration) {
        this.expiration = expiration;
    }

    public long getNotValidBefore() {
        return notValidBefore;
    }

    public void setNotValidBefore(long notValidBefore) {
        this.notValidBefore = notValidBefore;
    }

    public long getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(long issuedAt) {
        this.issuedAt = issuedAt;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getAudience() {
        return audience;
    }

    public void setAudience(String audience) {
        this.audience = audience;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getAuthorizedParty() {
        return authorizedParty;
    }

    public void setAuthorizedParty(String authorizedParty) {
        this.authorizedParty = authorizedParty;
    }

    public long getAuthorizedTime() {
        return authorizedTime;
    }

    public void setAuthorizedTime(long authorizedTime) {
        this.authorizedTime = authorizedTime;
    }

    public String getSessionState() {
        return sessionState;
    }

    public void setSessionState(String sessionState) {
        this.sessionState = sessionState;
    }

    public String getAuthorizationContextClass() {
        return authorizationContextClass;
    }

    public void setAuthorizationContextClass(String authorizationContextClass) {
        this.authorizationContextClass = authorizationContextClass;
    }

    public String[] getAllowedOrigins() {
        return allowedOrigins;
    }

    public void setAllowedOrigins(String[] allowedOrigins) {
        this.allowedOrigins = allowedOrigins;
    }

    public Map<String, Object> getRealmAccess() {
        return realmAccess;
    }

    public void setRealmAccess(Map<String, Object> realmAccess) {
        this.realmAccess = realmAccess;
    }

    public Map<String, Object> getResourceAccess() {
        return resourceAccess;
    }

    public void setResourceAccess(Map<String, Object> resourceAccess) {
        this.resourceAccess = resourceAccess;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public Boolean getEmailVerified() {
        return emailVerified;
    }

    public void setEmailVerified(Boolean emailVerified) {
        this.emailVerified = emailVerified;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPreferredUsername() {
        return preferredUsername;
    }

    public void setPreferredUsername(String preferredUsername) {
        this.preferredUsername = preferredUsername;
    }

    public String getGivenName() {
        return givenName;
    }

    public void setGivenName(String givenName) {
        this.givenName = givenName;
    }

    public String getFamilyName() {
        return familyName;
    }

    public void setFamilyName(String familyName) {
        this.familyName = familyName;
    }

}
