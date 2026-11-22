package authserver.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

/** Usuários de teste + promoção de administradores (bootstrap). Senhas vêm do ambiente. */
@Component
public class UserSeeder implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(UserSeeder.class);

    private final UserService users;
    private final String adminPassword;
    private final String userPassword;
    private final String bootstrapAdmins;

    public UserSeeder(UserService users,
                      @Value("${oidc.seed-admin-password}") String adminPassword,
                      @Value("${oidc.seed-user-password}") String userPassword,
                      @Value("${oidc.bootstrap-admins:}") String bootstrapAdmins) {
        this.users = users;
        this.adminPassword = adminPassword;
        this.userPassword = userPassword;
        this.bootstrapAdmins = bootstrapAdmins;
    }

    @Override
    public void run(ApplicationArguments args) {
        users.seedIfAbsent("sub-admin-001", "admin", "Administrador ONG", "admin@ong.local", adminPassword, "admin");
        users.seedIfAbsent("sub-user-002", "operador", "Operador Balcão", "operador@ong.local", userPassword, "user");
        for (String name : bootstrapAdmins.split(",")) {
            if (!name.isBlank()) {
                users.promote(name, "admin");
                log.info("Usuário promovido a admin (bootstrap): {}", name.trim());
            }
        }
    }
}
