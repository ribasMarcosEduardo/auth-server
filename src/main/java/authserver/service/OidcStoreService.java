package authserver.service;

import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

@Service
public class OidcStoreService {

    private static final int MAX_FAILS_PER_USER_IP = 5;     // ip + username
    private static final int MAX_FAILS_PER_IP = 20;         // ip (qualquer usuário)
    private static final long WINDOW_SECONDS = 300;
    private static final long CODE_RETENTION_SECONDS = 600; // guarda o code usado p/ detectar reuso

    public static class AuthCodeRecord {
        public final String code;
        public final String clientId;
        public final String redirectUri;
        public final String codeChallenge;
        public final String sub;
        public final String nonce;
        public final String scope;
        public final Instant expiresAt;
        /** Atômico: dois /token simultâneos com o mesmo code nunca passam juntos. */
        public final AtomicBoolean used = new AtomicBoolean(false);
        public final List<String> issuedAccessTokens = Collections.synchronizedList(new ArrayList<>());

        public AuthCodeRecord(String code, String clientId, String redirectUri, String codeChallenge,
                              String sub, String nonce, String scope, Instant expiresAt) {
            this.code = code;
            this.clientId = clientId;
            this.redirectUri = redirectUri;
            this.codeChallenge = codeChallenge;
            this.sub = sub;
            this.nonce = nonce;
            this.scope = scope;
            this.expiresAt = expiresAt;
        }
    }

    public record AccessTokenRecord(String token, String sub, String scope, Instant expiresAt) {}

    private final SecureRandom secureRandom = new SecureRandom();
    private static final int MAX_REGISTRATIONS_PER_IP = 5;   // por hora
    private static final long REGISTRATION_WINDOW_SECONDS = 3600;

    private final UserService userService;

    private final Map<String, AuthCodeRecord> authCodes = new ConcurrentHashMap<>();
    private final Map<String, AccessTokenRecord> activeAccessTokens = new ConcurrentHashMap<>();
    private final Map<String, List<Instant>> failedAttempts = new ConcurrentHashMap<>();
    private final Map<String, List<Instant>> registrations = new ConcurrentHashMap<>();

    public OidcStoreService(UserService userService) {
        this.userService = userService;
    }

    /** Limite de cadastros por IP (anti-abuso). Conta a tentativa se permitida. */
    public boolean allowRegistration(String ip) {
        Instant cutoff = Instant.now().minusSeconds(REGISTRATION_WINDOW_SECONDS);
        List<Instant> list = registrations.computeIfAbsent(ip, k -> Collections.synchronizedList(new ArrayList<>()));
        synchronized (list) {
            list.removeIf(t -> t.isBefore(cutoff));
            if (list.size() >= MAX_REGISTRATIONS_PER_IP) {
                return false;
            }
            list.add(Instant.now());
            return true;
        }
    }

    // ---------------------------------------------------------------- rate limiting

    private static String userKey(String ip, String username) {
        String u = username == null ? "" : username.trim().toLowerCase();
        if (u.length() > 64) {
            u = u.substring(0, 64);
        }
        return ip + ":" + u;
    }

    private long recentFailures(String key) {
        Instant cutoff = Instant.now().minusSeconds(WINDOW_SECONDS);
        List<Instant> list = failedAttempts.get(key);
        if (list == null) {
            return 0;
        }
        synchronized (list) {
            list.removeIf(t -> t.isBefore(cutoff));
            return list.size();
        }
    }

    public boolean isBlocked(String ip, String username) {
        return recentFailures(userKey(ip, username)) >= MAX_FAILS_PER_USER_IP
                || recentFailures("ip:" + ip) >= MAX_FAILS_PER_IP;
    }

    private void registerFailure(String ip, String username) {
        for (String key : new String[]{userKey(ip, username), "ip:" + ip}) {
            failedAttempts.computeIfAbsent(key, k -> Collections.synchronizedList(new ArrayList<>()))
                    .add(Instant.now());
        }
    }

    // ---------------------------------------------------------------- autenticação

    public Optional<UserRecord> authenticate(String username, String rawPassword, String clientIp) {
        if (isBlocked(clientIp, username)) {
            return Optional.empty();
        }
        Optional<UserRecord> user = userService.verifyCredentials(username, rawPassword);
        if (user.isEmpty()) {
            registerFailure(clientIp, username);
            return Optional.empty();
        }
        failedAttempts.remove(userKey(clientIp, username));
        return user;
    }

    public UserRecord findBySub(String sub) {
        return userService.findBySub(sub).orElse(null);
    }

    // ---------------------------------------------------------------- authorization code

    public String newOpaqueToken() {
        byte[] bytes = new byte[32]; // 256 bits
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public String createAuthorizationCode(String clientId, String redirectUri, String codeChallenge,
                                          String sub, String nonce, String scope) {
        purgeExpired();
        String code = newOpaqueToken();
        authCodes.put(code, new AuthCodeRecord(
                code, clientId, redirectUri, codeChallenge, sub, nonce, scope, Instant.now().plusSeconds(60)));
        return code;
    }

    private void purgeExpired() {
        Instant now = Instant.now();
        authCodes.values().removeIf(c -> now.isAfter(c.expiresAt.plusSeconds(CODE_RETENTION_SECONDS)));
        activeAccessTokens.values().removeIf(t -> now.isAfter(t.expiresAt()));
    }

    public AuthCodeRecord getCode(String code) {
        return authCodes.get(code);
    }

    public void revokeTokensForCode(AuthCodeRecord record) {
        synchronized (record.issuedAccessTokens) {
            for (String token : record.issuedAccessTokens) {
                activeAccessTokens.remove(token);
            }
            record.issuedAccessTokens.clear();
        }
    }

    public void storeAccessToken(AuthCodeRecord codeRecord, String token, String sub, String scope, long ttlSeconds) {
        codeRecord.issuedAccessTokens.add(token);
        activeAccessTokens.put(token, new AccessTokenRecord(token, sub, scope, Instant.now().plusSeconds(ttlSeconds)));
    }

    public Optional<AccessTokenRecord> validateAccessToken(String token) {
        AccessTokenRecord rec = activeAccessTokens.get(token);
        if (rec == null || Instant.now().isAfter(rec.expiresAt())) {
            activeAccessTokens.remove(token);
            return Optional.empty();
        }
        return Optional.of(rec);
    }

    // ---------------------------------------------------------------- utilitários de segurança

    public boolean verifyPkceS256(String codeVerifier, String expectedChallenge) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            String computed = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
            return constantTimeEquals(computed, expectedChallenge);
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
}
