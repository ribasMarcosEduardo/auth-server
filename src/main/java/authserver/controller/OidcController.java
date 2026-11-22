package authserver.controller;

import authserver.config.RsaKeyManager;
import authserver.service.OidcStoreService;
import authserver.service.OidcStoreService.AccessTokenRecord;
import authserver.service.OidcStoreService.AuthCodeRecord;
import authserver.service.UserRecord;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;

@Controller
@RequiredArgsConstructor
public class OidcController {

    private static final Logger log = LoggerFactory.getLogger(OidcController.class);

    private static final Set<String> SUPPORTED_SCOPES = Set.of("openid", "profile", "email");
    private static final Pattern CODE_VERIFIER = Pattern.compile("^[A-Za-z0-9\\-._~]{43,128}$"); // RFC 7636 §4.1
    private static final Pattern CODE_CHALLENGE = Pattern.compile("^[A-Za-z0-9\\-_]{43}$");      // BASE64URL(SHA256)
    private static final long TOKEN_TTL_SECONDS = 900;

    private final RsaKeyManager keyManager;
    private final OidcStoreService store;

    @Value("${oidc.issuer}")
    private String issuer;

    @Value("${oidc.client-id}")
    private String configuredClientId;

    @Value("${oidc.client-secret}")
    private String configuredClientSecret;

    @Value("${oidc.redirect-uri}")
    private String configuredRedirectUri;

    @Value("${oidc.post-logout-redirect-uri}")
    private String postLogoutRedirectUri;

    /** Grants que o cliente registrado pode usar (CSV). */
    @Value("${oidc.client-grant-types:authorization_code}")
    private String clientGrantTypesCsv;

    // ------------------------------------------------------------------ descoberta / JWKS

    @GetMapping(value = "/.well-known/openid-configuration", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public Map<String, Object> discovery() {
        return Map.ofEntries(
                Map.entry("issuer", issuer),
                Map.entry("authorization_endpoint", issuer + "/authorize"),
                Map.entry("token_endpoint", issuer + "/token"),
                Map.entry("userinfo_endpoint", issuer + "/userinfo"),
                Map.entry("jwks_uri", issuer + "/jwks.json"),
                Map.entry("end_session_endpoint", issuer + "/logout"),
                Map.entry("scopes_supported", List.of("openid", "profile", "email")),
                Map.entry("response_types_supported", List.of("code")),
                Map.entry("grant_types_supported", List.of("authorization_code")),
                Map.entry("subject_types_supported", List.of("public")),
                Map.entry("code_challenge_methods_supported", List.of("S256")),
                Map.entry("id_token_signing_alg_values_supported", List.of("RS256")),
                Map.entry("token_endpoint_auth_methods_supported", List.of("client_secret_post", "client_secret_basic")),
                Map.entry("claims_supported", List.of("iss", "sub", "aud", "exp", "iat", "nonce", "azp",
                        "name", "email", "email_verified", "role"))
        );
    }

    @GetMapping(value = "/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public Map<String, Object> jwks() {
        return keyManager.getJwkSetJson();
    }

    // ------------------------------------------------------------------ /authorize

    @GetMapping("/authorize")
    public String authorizeGet(
            @RequestParam(required = false) String response_type,
            @RequestParam(required = false) String client_id,
            @RequestParam(required = false) String redirect_uri,
            @RequestParam(required = false) String scope,
            @RequestParam(required = false) String state,
            @RequestParam(required = false) String nonce,
            @RequestParam(required = false) String code_challenge,
            @RequestParam(required = false) String code_challenge_method,
            Model model,
            HttpServletResponse response) {

        // 1) cliente / redirect_uri inválidos: NUNCA redireciona (RFC 6749 §4.1.2.1)
        if (!clientAndRedirectValid(client_id, redirect_uri)) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            model.addAttribute("erro", "invalid_request: client_id ou redirect_uri inválido.");
            return "erro";
        }

        // 2) demais parâmetros: aqui já é seguro devolver o erro à redirect_uri cadastrada
        String[] err = validateAuthParams(response_type, scope, state, nonce, code_challenge, code_challenge_method);
        if (err != null) {
            return redirectError(redirect_uri, err[0], err[1], state);
        }

        populateFormModel(model, client_id, redirect_uri, scope, state, nonce, code_challenge);
        return "login";
    }

    @PostMapping("/authorize")
    public String authorizePost(
            @RequestParam(required = false) String username,
            @RequestParam(required = false) String password,
            @RequestParam(defaultValue = "false") boolean consent,
            @RequestParam(required = false) String client_id,
            @RequestParam(required = false) String redirect_uri,
            @RequestParam(required = false) String scope,
            @RequestParam(required = false) String state,
            @RequestParam(required = false) String nonce,
            @RequestParam(required = false) String code_challenge,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model) {

        if (!clientAndRedirectValid(client_id, redirect_uri)) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            model.addAttribute("erro", "invalid_request: client_id ou redirect_uri inválido.");
            return "erro";
        }

        // revalida tudo: os hidden fields do formulário também são entrada do usuário
        String[] err = validateAuthParams("code", scope, state, nonce, code_challenge, "S256");
        if (err != null) {
            return redirectError(redirect_uri, err[0], err[1], state);
        }

        String clientIp = request.getRemoteAddr();
        if (store.isBlocked(clientIp, username)) {
            log.warn("Login bloqueado por rate limiting: ip={}", clientIp);
            response.setStatus(429);
            model.addAttribute("erroLogin", "Muitas tentativas. Tente novamente em alguns minutos.");
            populateFormModel(model, client_id, redirect_uri, scope, state, nonce, code_challenge);
            return "login";
        }

        Optional<UserRecord> userOpt = store.authenticate(username, password, clientIp);
        if (userOpt.isEmpty()) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            model.addAttribute("erroLogin", "Credenciais inválidas."); // genérica: não revela se o usuário existe
            populateFormModel(model, client_id, redirect_uri, scope, state, nonce, code_challenge);
            return "login";
        }

        if (!consent) {
            return redirectError(redirect_uri, "access_denied", null, state);
        }

        // sessão do servidor de autorização com id rotacionado após o login
        request.getSession(true);
        request.changeSessionId();
        request.getSession().setAttribute("AUTH_SUB", userOpt.get().sub());

        String code = store.createAuthorizationCode(client_id, redirect_uri, code_challenge,
                userOpt.get().sub(), nonce, scope);

        Map<String, String> params = new LinkedHashMap<>();
        params.put("code", code);
        params.put("state", state); // devolvido byte a byte idêntico (URL-encode/decode simétrico)
        return "redirect:" + appendQuery(redirect_uri, params);
    }

    private boolean clientAndRedirectValid(String clientId, String redirectUri) {
        return OidcStoreService.constantTimeEquals(configuredClientId, clientId)
                && configuredRedirectUri.equals(redirectUri); // comparação EXATA de string
    }

    /** @return {erro, descrição} ou null se os parâmetros estão ok. */
    private String[] validateAuthParams(String responseType, String scope, String state, String nonce,
                                        String codeChallenge, String codeChallengeMethod) {
        if (!"code".equals(responseType)) {
            return new String[]{"unsupported_response_type", "Somente response_type=code é aceito."};
        }
        if (state == null || state.isBlank()) {
            return new String[]{"invalid_request", "Parâmetro state ausente."};
        }
        if (nonce == null || nonce.isBlank()) {
            return new String[]{"invalid_request", "Parâmetro nonce ausente."};
        }
        if (!"S256".equals(codeChallengeMethod)) {
            return new String[]{"invalid_request", "code_challenge_method deve ser S256."};
        }
        if (codeChallenge == null || !CODE_CHALLENGE.matcher(codeChallenge).matches()) {
            return new String[]{"invalid_request", "code_challenge ausente ou malformado."};
        }
        if (scope == null || scope.isBlank()) {
            return new String[]{"invalid_scope", "Parâmetro scope ausente."};
        }
        List<String> scopes = Arrays.asList(scope.trim().split(" +"));
        if (!scopes.contains("openid") || !SUPPORTED_SCOPES.containsAll(scopes)) {
            return new String[]{"invalid_scope", "Escopo desconhecido ou sem openid."};
        }
        return null;
    }

    private String redirectError(String redirectUri, String error, String description, String state) {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("error", error);
        if (description != null) {
            params.put("error_description", description);
        }
        if (state != null && !state.isBlank()) {
            params.put("state", state);
        }
        return "redirect:" + appendQuery(redirectUri, params);
    }

    private static String appendQuery(String base, Map<String, String> params) {
        StringBuilder sb = new StringBuilder(base).append(base.contains("?") ? '&' : '?');
        boolean first = true;
        for (Map.Entry<String, String> e : params.entrySet()) {
            if (!first) {
                sb.append('&');
            }
            first = false;
            sb.append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8))
                    .append('=')
                    .append(URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8));
        }
        return sb.toString();
    }

    private void populateFormModel(Model model, String clientId, String redirectUri, String scope,
                                   String state, String nonce, String codeChallenge) {
        model.addAttribute("client_id", clientId);
        model.addAttribute("redirect_uri", redirectUri);
        model.addAttribute("scope", scope);
        model.addAttribute("state", state);
        model.addAttribute("nonce", nonce);
        model.addAttribute("code_challenge", codeChallenge);
    }

    // ------------------------------------------------------------------ /token

    @PostMapping(value = "/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<?> token(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authHeader,
            @RequestParam(required = false) String grant_type,
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String redirect_uri,
            @RequestParam(required = false) String code_verifier,
            @RequestParam(required = false) String client_id,
            @RequestParam(required = false) String client_secret) throws Exception {

        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CACHE_CONTROL, "no-store");
        headers.add(HttpHeaders.PRAGMA, "no-cache");

        // --- autenticação do cliente (client_secret_basic ou client_secret_post)
        String resolvedClientId = client_id;
        String resolvedSecret = client_secret;
        if (authHeader != null && authHeader.regionMatches(true, 0, "Basic ", 0, 6)) {
            try {
                String decoded = new String(Base64.getDecoder().decode(authHeader.substring(6).trim()),
                        StandardCharsets.UTF_8);
                String[] parts = decoded.split(":", 2);
                if (parts.length == 2) {
                    resolvedClientId = parts[0];
                    resolvedSecret = parts[1];
                }
            } catch (IllegalArgumentException e) {
                return invalidClient(headers);
            }
        }
        if (!OidcStoreService.constantTimeEquals(configuredClientId, resolvedClientId)
                || !OidcStoreService.constantTimeEquals(configuredClientSecret, resolvedSecret)) {
            return invalidClient(headers);
        }

        if (grant_type == null || grant_type.isBlank()) {
            return error(headers, HttpStatus.BAD_REQUEST, "invalid_request", "grant_type ausente.");
        }
        if (!"authorization_code".equals(grant_type)) {
            return error(headers, HttpStatus.BAD_REQUEST, "unsupported_grant_type", null);
        }
        if (!Arrays.asList(clientGrantTypesCsv.split("\\s*,\\s*")).contains(grant_type)) {
            return error(headers, HttpStatus.BAD_REQUEST, "unauthorized_client",
                    "Cliente não autorizado a usar este grant.");
        }
        if (code == null || code.isBlank() || redirect_uri == null || code_verifier == null) {
            return error(headers, HttpStatus.BAD_REQUEST, "invalid_request",
                    "code, redirect_uri e code_verifier são obrigatórios.");
        }

        AuthCodeRecord codeRec = store.getCode(code);
        if (codeRec == null || !codeRec.clientId.equals(resolvedClientId)) {
            return error(headers, HttpStatus.BAD_REQUEST, "invalid_grant", null);
        }

        // Uso único e ATÔMICO. Se já foi usado: reuso => revoga tudo emitido a partir dele.
        if (!codeRec.used.compareAndSet(false, true)) {
            log.warn("Reuso de authorization code detectado: revogando tokens emitidos.");
            store.revokeTokensForCode(codeRec);
            return error(headers, HttpStatus.BAD_REQUEST, "invalid_grant", "Authorization code já utilizado.");
        }
        // (a partir daqui o code está "queimado", mesmo que a validação abaixo falhe)

        if (Instant.now().isAfter(codeRec.expiresAt)
                || !codeRec.redirectUri.equals(redirect_uri)
                || !CODE_VERIFIER.matcher(code_verifier).matches()
                || !store.verifyPkceS256(code_verifier, codeRec.codeChallenge)) {
            return error(headers, HttpStatus.BAD_REQUEST, "invalid_grant", null);
        }

        UserRecord user = store.findBySub(codeRec.sub);
        Instant now = Instant.now();

        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(JOSEObjectType.JWT)
                .keyID(keyManager.getCurrentSigningKey().getKeyID())
                .build();

        JWTClaimsSet idClaims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(user.sub())
                .audience(configuredClientId)
                .expirationTime(Date.from(now.plusSeconds(TOKEN_TTL_SECONDS)))
                .issueTime(Date.from(now))
                .claim("nonce", codeRec.nonce)
                .claim("azp", configuredClientId)
                .claim("name", user.name())
                .claim("email", user.email())
                .claim("email_verified", user.emailVerified())
                .claim("role", user.role())
                .claim("preferred_username", user.username())
                .build();

        SignedJWT idJwt = new SignedJWT(jwsHeader, idClaims);
        idJwt.sign(new RSASSASigner(keyManager.getCurrentSigningKey()));

        // access_token OPACO (não é JWT): só serve para o /userinfo
        String accessToken = store.newOpaqueToken();
        store.storeAccessToken(codeRec, accessToken, user.sub(), codeRec.scope, TOKEN_TTL_SECONDS);

        // Sem refresh_token: o servidor só suporta grant authorization_code (ver discovery).
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("access_token", accessToken);
        body.put("token_type", "Bearer");
        body.put("expires_in", TOKEN_TTL_SECONDS);
        body.put("scope", codeRec.scope);
        body.put("id_token", idJwt.serialize());
        return new ResponseEntity<>(body, headers, HttpStatus.OK);
    }

    private ResponseEntity<?> invalidClient(HttpHeaders headers) {
        headers.add(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"auth-server\"");
        return new ResponseEntity<>(Map.of("error", "invalid_client"), headers, HttpStatus.UNAUTHORIZED);
    }

    private ResponseEntity<?> error(HttpHeaders headers, HttpStatus status, String error, String description) {
        Map<String, String> body = new LinkedHashMap<>();
        body.put("error", error);
        if (description != null) {
            body.put("error_description", description);
        }
        return new ResponseEntity<>(body, headers, status);
    }

    // ------------------------------------------------------------------ /userinfo

    @RequestMapping(value = "/userinfo", method = {RequestMethod.GET, RequestMethod.POST},
            produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<?> userinfo(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authHeader) {

        if (authHeader == null || !authHeader.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .header(HttpHeaders.WWW_AUTHENTICATE, "Bearer")
                    .body(Map.of("error", "invalid_token"));
        }

        Optional<AccessTokenRecord> tokenOpt = store.validateAccessToken(authHeader.substring(7).trim());
        if (tokenOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .header(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\"")
                    .body(Map.of("error", "invalid_token"));
        }

        UserRecord user = store.findBySub(tokenOpt.get().sub());
        List<String> scopes = Arrays.asList(tokenOpt.get().scope().split(" +"));

        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", user.sub());
        if (scopes.contains("profile")) {
            claims.put("name", user.name());
            claims.put("role", user.role());
            claims.put("preferred_username", user.username());
        }
        if (scopes.contains("email")) {
            claims.put("email", user.email());
            claims.put("email_verified", user.emailVerified());
        }
        return ResponseEntity.ok(claims);
    }

    // ------------------------------------------------------------------ /logout

    /** Passo 1 do logout iniciado pela aplicação: página que submete o POST /logout (com token CSRF). */
    @GetMapping("/logout")
    public String logoutPage(@RequestParam(required = false) String post_logout_redirect_uri, Model model) {
        if (postLogoutRedirectUri.equals(post_logout_redirect_uri)) {   // só a URI cadastrada, comparação exata
            model.addAttribute("postLogoutRedirectUri", post_logout_redirect_uri);
        }
        return "logout";
    }

    /** Encerra a sessão no Servidor de Autorização. */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpSession session,
                                    @RequestParam(required = false) String post_logout_redirect_uri) {
        session.invalidate();
        if (postLogoutRedirectUri.equals(post_logout_redirect_uri)) {
            return ResponseEntity.status(HttpStatus.FOUND)
                    .header(HttpHeaders.LOCATION, postLogoutRedirectUri).build();
        }
        return ResponseEntity.ok(Map.of("status", "logged_out"));
    }
}
