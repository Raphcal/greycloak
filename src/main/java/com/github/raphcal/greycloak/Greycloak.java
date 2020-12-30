package com.github.raphcal.greycloak;

import com.github.raphcal.localserver.HttpRequest;
import com.github.raphcal.localserver.HttpResponse;
import com.github.raphcal.localserver.HttpServlet;
import com.github.raphcal.logdorak.Logger;
import com.google.gson.Gson;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.ws.rs.core.Cookie;
import org.jboss.resteasy.util.CookieParser;

/**
 * Mock simulant un serveur Keycloak.
 *
 * @author Raphaël Calabro (ddaeke-github at yahoo.fr)
 */
public class Greycloak extends HttpServlet {

    private static final Logger LOGGER = new Logger(Greycloak.class);

    private static final String CONTEXT = "/auth";

    private static final String PUBLIC_EXPONENT = "AQAB";
    private static final int KEY_SIZE = 2048;

    private static final String SESSION_COOKIE_NAME = "KEYCLOAK_SESSION";
    /**
     * Durée avant l'expiration du cookie de session (9 heures).
     */
    private static final int COOKIE_EXPIRE = 60 * 60 * 9;

    private final Pattern openIdConfigurationPattern = Pattern.compile('^' + CONTEXT + "/realms/([a-zA-Z0-9-]+)/.well-known/openid-configuration/?$");
    private final Pattern certificatesPattern = Pattern.compile('^' + CONTEXT + "/realms/([a-zA-Z0-9-]+)/protocol/openid-connect/certs/?$");
    private final Pattern authPattern = Pattern.compile('^' + CONTEXT + "/realms/([a-zA-Z0-9-]+)/protocol/openid-connect/auth/?$");
    private final Pattern logoutPattern = Pattern.compile('^' + CONTEXT + "/realms/([a-zA-Z0-9-]+)/protocol/openid-connect/logout/?$");
    private final Pattern tokenPattern = Pattern.compile('^' + CONTEXT + "/realms/([a-zA-Z0-9-]+)/protocol/openid-connect/token/?$");
    private final Pattern accountPattern = Pattern.compile('^' + CONTEXT + "/realms/([a-zA-Z0-9-]+)/account/?$");

    private final Gson gson = new Gson();

    private final KeyPair keyPair;
    private final String kid = generateKeyIdentifier();

    private final HashMap<String, Session> sessions = new HashMap<>();

    public Greycloak() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        keyPair = generateRSAKeyPair();
    }

    @Override
    public void doGet(HttpRequest request, HttpResponse response) throws Exception {
        response.setCharset(StandardCharsets.UTF_8);
        final HashMap<String, String> queryParameters = new HashMap<>();
        final String target = parseQueryParameters(request.getTarget(), queryParameters);

        final Matcher openIdConfigurationMatcher = openIdConfigurationPattern.matcher(target);
        final Matcher certificatesMatcher = certificatesPattern.matcher(target);
        final Matcher authMatcher = authPattern.matcher(target);
        final Matcher logoutMatcher = logoutPattern.matcher(target);
        final Matcher accountMatcher = accountPattern.matcher(target);

        if (openIdConfigurationMatcher.matches()) {
            final String realm = openIdConfigurationMatcher.group(1);
            response.setContentType("application/json");
            response.setContent("{"
                    + "\"issuer\":\"http://localhost:9080/auth/realms/" + realm + "\","
                    + "\"authorization_endpoint\":\"http://localhost:9080/auth/realms/" + realm + "/protocol/openid-connect/auth\","
                    + "\"token_endpoint\":\"http://localhost:9080/auth/realms/" + realm + "/protocol/openid-connect/token\","
                    + "\"token_introspection_endpoint\":\"http://localhost:9080/auth/realms/" + realm + "/protocol/openid-connect/token/introspect\","
                    + "\"userinfo_endpoint\":\"http://localhost:9080/auth/realms/" + realm + "/protocol/openid-connect/userinfo\","
                    + "\"end_session_endpoint\":\"http://localhost:9080/auth/realms/" + realm + "/protocol/openid-connect/logout\","
                    + "\"jwks_uri\":\"http://localhost:9080/auth/realms/" + realm + "/protocol/openid-connect/certs\","
                    + "\"check_session_iframe\":\"http://localhost:9080/auth/realms/" + realm + "/protocol/openid-connect/login-status-iframe.html\","
                    + "\"grant_types_supported\":[\"authorization_code\",\"implicit\",\"refresh_token\","
                    + "\"password\",\"client_credentials\"],"
                    + "\"response_types_supported\":[\"code\",\"none\",\"id_token\",\"token\",\"id_token token\",\"code id_token\",\"code token\",\"code id_token token\"],"
                    + "\"subject_types_supported\":[\"public\",\"pairwise\"],"
                    + "\"id_token_signing_alg_values_supported\":[\"RS256\"],"
                    + "\"userinfo_signing_alg_values_supported\":[\"RS256\"],"
                    + "\"request_object_signing_alg_values_supported\":[\"none\",\"RS256\"],"
                    + "\"response_modes_supported\":[\"query\",\"fragment\",\"form_post\"],"
                    + "\"registration_endpoint\":\"http://localhost:9080/auth/realms/" + realm + "/clients-registrations/openid-connect\","
                    + "\"token_endpoint_auth_methods_supported\":[\"private_key_jwt\",\"client_secret_basic\",\"client_secret_post\"],"
                    + "\"token_endpoint_auth_signing_alg_values_supported\":[\"RS256\"],"
                    + "\"claims_supported\":[\"sub\",\"iss\",\"auth_time\",\"name\",\"given_name\",\"family_name\",\"preferred_username\",\"email\"],"
                    + "\"claim_types_supported\":[\"normal\"],"
                    + "\"claims_parameter_supported\":false,\"scopes_supported\":[\"openid\",\"offline_access\"],"
                    + "\"request_parameter_supported\":true,"
                    + "\"request_uri_parameter_supported\":true"
                    + "}");
        } else if (certificatesMatcher.matches()) {
            response.setContentType("application/json");
            response.setContent("{\"keys\":[{\"kid\":\"" + kid + "\",\"kty\":\"RSA\",\"alg\":\"RS256\",\"use\":\"sig\",\"n\":\"" + getPublicKey() + "\",\"e\":\"" + PUBLIC_EXPONENT + "\"}]}");
        } else if (authMatcher.matches()) {
            response.setContentType("text/html");
            final String realm = authMatcher.group(1);
            final Session session = new Session(realm);
            sessions.put(session.getId(), session);
            renewSessionCookie(response, session);
            final String redirectUri = queryParameters.get("redirect_uri");
            final String redirectFragment = queryParameters.get("redirect_fragment");
            final String state = queryParameters.get("state");
            final String nonce = queryParameters.get("nonce");
            final ResponseMode responseMode = ResponseMode.valueOf(queryParameters.getOrDefault("response_mode", "query").toUpperCase());
            response.setContent(loginPage(realm, redirectUri, redirectFragment, state, nonce, responseMode));
        } else if (logoutMatcher.matches()) {
            final Session session = getSession(request);
            if (session != null) {
                response.setHeader("Set-Cookie", SESSION_COOKIE_NAME + "=none; Max-Age=0");
                sessions.remove(session.getId());
            }
            response.setStatusCode(302);
            response.setStatusMessage("Found");
            response.setHeader("Location", queryParameters.get("redirect_uri"));
        } else if (accountMatcher.matches()) {
            allowCrossOrigin(request, response);
            response.setContentType("application/json");
            final JWTPayload payload = new JWTPayload();
            payload.setName("Alain Dupont-Mine");
            payload.setGivenName("Alain");
            payload.setFamilyName("Dupont-Mine");
            payload.setUsername("U031458");
            response.setContent(gson.toJson(payload));
        } else {
            notFound(response);
        }
    }

    private void renewSessionCookie(HttpResponse response, Session session) {
        response.setHeader("Set-Cookie", SESSION_COOKIE_NAME + '=' + session.getRealm() + '/' + session.getId() + "; Path=/auth/realms/" + session.getRealm() + "/; Max-Age=" + COOKIE_EXPIRE);
    }

    @Override
    public void doPost(HttpRequest request, HttpResponse response) throws Exception {
        response.setCharset(StandardCharsets.UTF_8);
        final HashMap<String, String> queryParameters = new HashMap<>();
        final String target = parseQueryParameters(request.getTarget(), queryParameters);

        final Matcher authMatcher = authPattern.matcher(target);
        final Matcher tokenMatcher = tokenPattern.matcher(target);

        if (authMatcher.matches()) {
            final Map<String, String> formValues = parseFormValues(request);
            if (formValues == null || formValues.isEmpty()) {
                response.setStatusCode(302);
                response.setStatusMessage("Found");
                response.setHeader("Location", request.getHeader("Referer"));
                return;
            }
            Session session = getSession(request);
            if (session == null) {
                session = new Session(authMatcher.group(1));
                sessions.put(session.getId(), session);
            }
            session.setNonce(formValues.get("nonce"));
            final ResponseMode responseMode = ResponseMode.valueOf(formValues.getOrDefault("response_mode", "query").toUpperCase());
            final String redirectUri = formValues.get("redirect_uri");
            final String redirectFragment = formValues.get("redirect_fragment");
            final String state = formValues.get("state");
            final String code = session.generateCode();
            String url = redirectUri;
            if (redirectFragment != null) {
                url += (url.indexOf(responseMode.getStart()) >= 0 ? '&' : responseMode.getStart()) + "redirect_fragment=" + redirectFragment;
            }
            url += (url.indexOf(responseMode.getStart()) >= 0 ? '&' : responseMode.getStart()) + "state=" + state;
            url += "&code=" + code;
            response.setStatusCode(302);
            response.setStatusMessage("Found");
            response.setHeader("Location", url);
            renewSessionCookie(response, session);
        } else if (tokenMatcher.matches()) {
            allowCrossOrigin(request, response);
            final Session session = getSession(request);
            if (session == null) {
                response.setStatusCode(401);
                response.setStatusMessage("Unauthorized");
                response.setContent("Session does not exists or is inactive");
                return;
            }
            final Pointer<String> reason = new Pointer<>();
            if (!isGrantValid(session, response, request, reason)) {
                response.setStatusCode(401);
                response.setStatusMessage("Unauthorized");
                response.setContent(reason.get());
                return;
            }
            final Token token = createToken(session);
            session.addRefreshToken(token.getRefreshToken());
            renewSessionCookie(response, session);
            response.setContentType("application/json");
            response.setContent(gson.toJson(token));
        } else {
            notFound(response);
        }
    }

    @Override
    public void doOptions(HttpRequest request, HttpResponse response) throws Exception {
        final String target = request.getTarget();
        if (tokenPattern.matcher(target).matches()
                || accountPattern.matcher(target).matches()) {
            allowCrossOrigin(request, response);
        }
    }

    private void notFound(HttpResponse response) {
        response.setStatusCode(404);
        response.setStatusMessage("Not Found");
    }

    private Map<String, String> parseURLEncodedValues(String encodedValues) throws UnsupportedEncodingException {
        if (encodedValues == null) {
            return Collections.emptyMap();
        }
        final HashMap<String, String> values = new HashMap<>();
        for (String parameter : encodedValues.split(Pattern.quote("&"))) {
            final String[] keyAndValue = parameter.split("=");
            if (keyAndValue.length == 2) {
                values.put(keyAndValue[0], URLDecoder.decode(keyAndValue[1], "utf-8"));
            } else if (keyAndValue.length == 1) {
                values.put(keyAndValue[0], "");
            }
        }
        return values;
    }

    private String parseQueryParameters(String target, Map<String, String> queryParameters) throws UnsupportedEncodingException {
        final int queryStart = target.indexOf('?');
        if (queryStart < 0) {
            return target;
        }
        queryParameters.putAll(parseURLEncodedValues(target.substring(queryStart + 1)));
        return target.substring(0, queryStart);
    }

    private void allowCrossOrigin(HttpRequest request, HttpResponse response) {
        final String origin = request.getHeader("Origin");
        response.setHeader("Access-Control-Allow-Origin", origin);
        response.setHeader("Access-Control-Allow-Methods", "GET,POST");
        response.setHeader("Access-Control-Allow-Headers", "Authorization");
        response.setHeader("Access-Control-Allow-Credentials", "true");
    }

    private KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        final BigInteger publicExponent = new BigInteger(1, Base64.getUrlDecoder().decode(PUBLIC_EXPONENT));
        keyGen.initialize(new RSAKeyGenParameterSpec(KEY_SIZE, publicExponent));
        return keyGen.genKeyPair();
    }

    private String getPublicKey() {
        final RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        return Base64.getUrlEncoder().encodeToString(publicKey.getModulus().toByteArray());
    }

    private String loginPage(String realm, String redirectUri, String redirectFragment, String state, String nonce, ResponseMode responseMode) {
        return "<!DOCTYPE html>\n"
                + "<html lang=\"en\">\n"
                + "<head>\n"
                + "<title>Log in to " + realm + "</title>\n"
                + "<style>\n"
                + "html {\n"
                + "    background: linear-gradient(135deg, #737373 0%,#090909 100%);\n"
                + "    height: 100%;\n"
                + "}\n"
                + "body {\n"
                + "    font-family: \"Open Sans\", Arial, Helvetica, sans-serif;\n"
                + "}\n"
                + "h1 {\n"
                + "    padding: 62px 10px 20px;\n"
                + "    text-align: center;\n"
                + "    color: #fff;\n"
                + "    font-weight: 400;\n"
                + "}\n"
                + "h2 {\n"
                + "    font-size: 24px;\n"
                + "    font-weight: 300;\n"
                + "    text-align: center;\n"
                + "}\n"
                + "form {\n"
                + "    width: 420px;\n"
                + "    margin: auto;\n"
                + "    background-color: #fff;\n"
                + "    padding: 20px 40px 30px 40px;\n"
                + "}\n"
                + "button {\n"
                + "    width: 100%;\n"
                + "    color: #fff;\n"
                + "    background-color: #0088ce;\n"
                + "    background-image: linear-gradient(to bottom, #39a5dc 0%, #0088ce 100%);\n"
                + "    background-repeat: repeat-x;\n"
                + "    filter: progid:DXImageTransform.Microsoft.gradient(startColorstr='#ff39a5dc', endColorstr='#ff0088ce', GradientType=0);\n"
                + "    border: 1px solid #00659c;\n"
                + "    border-radius: 1px;\n"
                + "    box-shadow: 0 2px 3px rgba(3, 3, 3, 0.1);\n"
                + "    padding: 6px 10px;\n"
                + "    margin-bottom: 0;\n"
                + "    font-size: 14px;\n"
                + "    line-height: 1.3333333;\n"
                + "    font-weight: 600;\n"
                + "    text-align: center;\n"
                + "    vertical-align: middle;\n"
                + "    cursor: pointer;\n"
                + "}\n"
                + "button:hover, button:focus, button:active {\n"
                + "    background-color: #0088ce;\n"
                + "    background-image: none;\n"
                + "}\n"
                + "</style>\n"
                + "</head>\n"
                + "<body>\n"
                + "<h1>" + realm + "</h1>\n"
                + "<form method=\"POST\" action=\"?\">\n"
                + "<h2>Log In</h2>\n"
                + hiddenInput("redirect_uri", redirectUri)
                + hiddenInput("redirect_fragment", redirectFragment)
                + hiddenInput("state", state)
                + (nonce != null ? hiddenInput("nonce", nonce) : "")
                + hiddenInput("response_mode", responseMode.name())
                + "<button>Log In</button>\n"
                + "</form>\n"
                + "</body>\n"
                + "</html>";
    }

    private String hiddenInput(String name, String value) {
        return value != null
                ? "<input type=\"hidden\" name=\"" + name + "\" value=\"" + value + "\">\n"
                : "";
    }

    private Session getSession(HttpRequest request) {
        final List<Cookie> cookies;
        try {
            cookies = CookieParser.parseCookies(request.getHeader("Cookie"));
        } catch (IllegalArgumentException e) {
            LOGGER.error("Erreur lors de la recherche du cookie de session", e);
            return null;
        }
        for (final Cookie cookie : cookies) {
            if (SESSION_COOKIE_NAME.equals(cookie.getName())) {
                final String value = cookie.getValue();
                final int separatorIndex = value.indexOf('/');
                if (separatorIndex > 0) {
                    return sessions.get(value.substring(separatorIndex + 1));
                }
            }
        }
        return null;
    }

    private Map<String, String> parseFormValues(HttpRequest request) throws UnsupportedEncodingException {
        if (!"application/x-www-form-urlencoded".equals(request.getContentType())) {
            return Collections.emptyMap();
        }
        return parseURLEncodedValues(request.getContent());
    }

    private boolean isGrantValid(Session session, HttpResponse response, HttpRequest request, Pointer<String> reason) throws IOException {
        final Map<String, String> values = parseFormValues(request);
        final String grantType = values.get("grant_type");
        if ("authorization_code".equals(grantType)) {
            final String code = values.get("code");
            if (code == null || !session.isCodeValid(code)) {
                reason.assign("Bad code");
            }
        } else if ("refresh_token".equals(grantType)) {
            if (!session.isRefreshTokenValid(values.get("refresh_token"))) {
                reason.assign("Given refresh token is invalid, has expired or has been revoked");
            }
        } else {
            reason.assign("Bad grant type");
        }
        return reason.isNull();
    }

    private Token createToken(Session session) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        final String subject = UUID.randomUUID().toString();

        final JWTHeader header = new JWTHeader("RS256", "JWT", kid);

        final JWTPayload refreshTokenPayload = createJWTPayload(session.getRealm(), subject, Token.REFRESH_TOKEN_EXPIRE);
        refreshTokenPayload.setType("ID");
        refreshTokenPayload.setNonce(session.getNonce());
        final JWT refreshToken = new JWT(header, refreshTokenPayload);
        refreshToken.signUsing(keyPair.getPrivate());

        final JWTPayload accessTokenPayload = createJWTPayload(session.getRealm(), subject, Token.ACCESS_TOKEN_EXPIRE);
        accessTokenPayload.setAudience("account");
        accessTokenPayload.setType("Bearer");
        accessTokenPayload.setNonce(session.getNonce());
        accessTokenPayload.setAllowedOrigins(new String[]{
            "http://localhost:4200",
            "http://localhost:4100",});
        final HashMap<String, Object> realmAccess = new HashMap<>();
        realmAccess.put(JWTPayload.REALM_ACCESS_ROLES, new String[]{
            "offline_access",
            "uma_authorization",
            "GRAALOD_ADMIN",
            "client-admin"
        });
        accessTokenPayload.setRealmAccess(realmAccess);
        accessTokenPayload.setScope("openid profile email");
        final HashMap<String, Object> resourceAccessAccount = new HashMap<>();
        resourceAccessAccount.put(JWTPayload.REALM_ACCESS_ROLES, new String[]{
            "manage-account",
            "manage-account-links",
            "view-profile"
        });
        final HashMap<String, Object> resourceAccess = new HashMap<>();
        resourceAccess.put("account", resourceAccessAccount);
        accessTokenPayload.setResourceAccess(resourceAccess);
        final JWT accessToken = new JWT(header, accessTokenPayload);
        accessToken.signUsing(keyPair.getPrivate());

        final Token token = new Token();
        token.setAccessToken(accessToken.toJson());
        token.setIdToken(refreshToken.toJson());
        token.setRefreshToken(refreshToken.toJson());

        return token;
    }

    private JWTPayload createJWTPayload(final String realm, final String subject, int expiration) {
        final JWTPayload payload = new JWTPayload();
        payload.setJwtIdentifier(UUID.randomUUID().toString());
        payload.setSessionState(UUID.randomUUID().toString());
        payload.setExpiration(Instant.now().plusSeconds(expiration).getEpochSecond());
        payload.setIssuedAt(Instant.now().getEpochSecond());
        payload.setAuthorizedTime(Instant.now().getEpochSecond());
        payload.setIssuer("http://localhost:9080/auth/realms/" + realm);
        payload.setAudience("you");
        payload.setAuthorizationContextClass("1");
        payload.setEmailVerified(Boolean.FALSE);
        payload.setSubject(subject);
        payload.setName("Alain Dupont-Mine");
        payload.setGivenName("Alain");
        payload.setFamilyName("Dupont-Mine");
        payload.setPreferredUsername("U031458");
        return payload;
    }

    private String generateKeyIdentifier() {
        final StringBuilder builder = new StringBuilder();
        final char[] characters = new char[]{
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'};
        for (int index = 0; index < 43; index++) {
            builder.append(characters[(int) (Math.random() * characters.length)]);
        }
        return builder.toString();
    }

}
