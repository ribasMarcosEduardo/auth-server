package authserver.service;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;

@Service
public class UserService {

    /** Erro de validação do cadastro, com mensagem segura para exibir ao usuário. */
    public static class RegistrationException extends RuntimeException {
        public RegistrationException(String message) {
            super(message);
        }
    }

    private static final Pattern USERNAME = Pattern.compile("^[a-z0-9._-]{3,32}$");
    private static final Pattern EMAIL = Pattern.compile("^[^@\\s]{1,64}@[^@\\s]{1,189}$");
    private static final int PASSWORD_MIN = 10;
    private static final int BCRYPT_MAX_BYTES = 72;   // bcrypt ignora o que passa de 72 bytes

    private final UserRepository users;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
    private final String dummyHash;

    public UserService(UserRepository users) {
        this.users = users;
        // hash "fantasma": equaliza o tempo de resposta quando o usuário não existe
        this.dummyHash = encoder.encode(UUID.randomUUID().toString());
    }

    // ------------------------------------------------------------------ autenticação

    public Optional<UserRecord> verifyCredentials(String username, String rawPassword) {
        String key = username == null ? "" : username.trim().toLowerCase();
        Optional<UserRecord> user = key.isEmpty() ? Optional.empty() : users.findByUsername(key);
        String hash = user.map(UserRecord::passwordHash).orElse(dummyHash);
        boolean ok = rawPassword != null && rawPassword.getBytes(StandardCharsets.UTF_8).length <= 1024
                && encoder.matches(rawPassword, hash);
        return (ok && user.isPresent()) ? user : Optional.empty();
    }

    public Optional<UserRecord> findBySub(String sub) {
        return users.findBySub(sub);
    }

    // ------------------------------------------------------------------ cadastro

    /** Cadastro self-service: a role é SEMPRE "adotante" e o e-mail nasce NÃO verificado. */
    public UserRecord register(String username, String name, String email, String password, String confirm) {
        String u = username == null ? "" : username.trim().toLowerCase();
        String n = name == null ? "" : name.trim();
        String e = email == null ? "" : email.trim().toLowerCase();

        if (!USERNAME.matcher(u).matches()) {
            throw new RegistrationException("Usuário inválido: use 3 a 32 caracteres (a-z, 0-9, ponto, hífen, sublinhado).");
        }
        if (n.length() < 2 || n.length() > 120 || n.chars().anyMatch(Character::isISOControl)) {
            throw new RegistrationException("Informe seu nome completo (2 a 120 caracteres).");
        }
        if (e.length() > 254 || !EMAIL.matcher(e).matches()) {
            throw new RegistrationException("E-mail inválido.");
        }
        if (password == null || password.length() < PASSWORD_MIN) {
            throw new RegistrationException("A senha deve ter no mínimo " + PASSWORD_MIN + " caracteres.");
        }
        if (password.getBytes(StandardCharsets.UTF_8).length > BCRYPT_MAX_BYTES) {
            throw new RegistrationException("A senha é longa demais (máximo de 72 bytes).");
        }
        if (!password.equals(confirm)) {
            throw new RegistrationException("A confirmação de senha não confere.");
        }
        if (password.toLowerCase().contains(u)) {
            throw new RegistrationException("A senha não pode conter o nome de usuário.");
        }
        if (users.existsByUsernameOrEmail(u, e)) {
            throw new RegistrationException("Usuário ou e-mail já cadastrado.");
        }

        UserRecord record = new UserRecord(UUID.randomUUID().toString(), u, encoder.encode(password), n, e, false, "adotante");
        try {
            users.insert(record);
        } catch (DuplicateKeyException ex) {
            throw new RegistrationException("Usuário ou e-mail já cadastrado.");
        }
        return record;
    }

    // ------------------------------------------------------------------ seed / bootstrap

    /** Cria um usuário de teste com sub fixo, se ainda não existir (idempotente). */
    public void seedIfAbsent(String sub, String username, String name, String email, String rawPassword, String role) {
        if (users.findByUsername(username).isPresent()) {
            return;
        }
        users.insert(new UserRecord(sub, username, encoder.encode(rawPassword), name, email, true, role));
    }

    public void promote(String username, String role) {
        users.updateRole(username.trim().toLowerCase(), role);
    }
}
