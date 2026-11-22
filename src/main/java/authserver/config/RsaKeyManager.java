package authserver.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Gerencia a chave RSA de assinatura do ID Token.
 * - A chave privada é persistida em arquivo local (fora do git) para sobreviver a reinícios.
 * - rotateKey() gera uma nova chave; a anterior continua publicada no JWKS durante a transição.
 * - A rotação roda automaticamente (oidc.key-rotation-minutes) e pode ser chamada manualmente.
 */
@Component
public class RsaKeyManager {

    private static final Logger log = LoggerFactory.getLogger(RsaKeyManager.class);
    private static final DateTimeFormatter KID_FMT = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");

    @Value("${oidc.signing-key-file:}")
    private String keyFile;

    private RSAKey currentKey;
    private final List<JWK> publishedPublicKeys = new ArrayList<>();

    @PostConstruct
    public synchronized void init() throws Exception {
        if (keyFile != null && !keyFile.isBlank() && Files.exists(Path.of(keyFile))) {
            currentKey = RSAKey.parse(Files.readString(Path.of(keyFile)));
            publishedPublicKeys.add(currentKey.toPublicJWK());
            log.info("Chave de assinatura carregada: kid={}", currentKey.getKeyID());
        } else {
            rotateKey();
        }
    }

    @Scheduled(fixedRateString = "${oidc.key-rotation-minutes:1440}",
            initialDelayString = "${oidc.key-rotation-minutes:1440}",
            timeUnit = TimeUnit.MINUTES)
    public synchronized void rotateKey() throws Exception {
        String kid = "key-" + LocalDateTime.now().format(KID_FMT);
        RSAKey newKey = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .keyID(kid)
                .generate();
        this.currentKey = newKey;
        publishedPublicKeys.add(0, newKey.toPublicJWK());
        // mantém a chave nova + a anterior (janela de transição)
        while (publishedPublicKeys.size() > 2) {
            publishedPublicKeys.remove(publishedPublicKeys.size() - 1);
        }
        persist(newKey);
        log.info("Nova chave de assinatura gerada: kid={} (chaves publicadas: {})", kid, publishedPublicKeys.size());
    }

    private void persist(RSAKey key) {
        if (keyFile == null || keyFile.isBlank()) {
            return;
        }
        try {
            Path p = Path.of(keyFile);
            if (p.getParent() != null) {
                Files.createDirectories(p.getParent());
            }
            Files.writeString(p, key.toJSONString());
            try {
                Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rw-------"));
            } catch (UnsupportedOperationException ignored) {
                // Windows: sem permissões POSIX
            }
        } catch (Exception e) {
            log.warn("Não foi possível persistir a chave de assinatura: {}", e.getMessage());
        }
    }

    public synchronized RSAKey getCurrentSigningKey() {
        return currentKey;
    }

    public synchronized Map<String, Object> getJwkSetJson() {
        return new JWKSet(new ArrayList<>(publishedPublicKeys)).toJSONObject(); // somente chaves públicas
    }
}
