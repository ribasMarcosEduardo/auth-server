package authserver.service;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/** Acesso aos usuários do servidor de autorização (somente consultas parametrizadas). */
@Repository
public class UserRepository {

    private static final RowMapper<UserRecord> MAPPER = (rs, i) -> new UserRecord(
            rs.getString("sub"), rs.getString("username"), rs.getString("password_hash"),
            rs.getString("name"), rs.getString("email"), rs.getBoolean("email_verified"), rs.getString("role"));

    private final JdbcTemplate jdbc;

    public UserRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Optional<UserRecord> findByUsername(String username) {
        return jdbc.query("SELECT * FROM users WHERE username = ?", MAPPER, username).stream().findFirst();
    }

    public Optional<UserRecord> findBySub(String sub) {
        return jdbc.query("SELECT * FROM users WHERE sub = ?", MAPPER, sub).stream().findFirst();
    }

    public boolean existsByUsernameOrEmail(String username, String email) {
        Integer n = jdbc.queryForObject("SELECT COUNT(*) FROM users WHERE username = ? OR email = ?",
                Integer.class, username, email);
        return n != null && n > 0;
    }

    /** @throws DuplicateKeyException se username/email/sub já existirem */
    public void insert(UserRecord u) {
        jdbc.update("INSERT INTO users (sub, username, email, email_verified, name, password_hash, role) "
                        + "VALUES (?, ?, ?, ?, ?, ?, ?)",
                u.sub(), u.username(), u.email(), u.emailVerified(), u.name(), u.passwordHash(), u.role());
    }

    public int updateRole(String username, String role) {
        return jdbc.update("UPDATE users SET role = ? WHERE username = ?", role, username);
    }
}
