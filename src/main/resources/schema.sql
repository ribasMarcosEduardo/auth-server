CREATE TABLE IF NOT EXISTS users (
    id             BIGINT AUTO_INCREMENT PRIMARY KEY,
    sub            VARCHAR(64)  NOT NULL UNIQUE,       -- identificador estável, nunca reatribuído
    username       VARCHAR(32)  NOT NULL UNIQUE,
    email          VARCHAR(254) NOT NULL UNIQUE,
    email_verified BOOLEAN      NOT NULL DEFAULT FALSE,
    name           VARCHAR(120) NOT NULL,
    password_hash  VARCHAR(100) NOT NULL,              -- bcrypt custo 12
    role           VARCHAR(20)  NOT NULL DEFAULT 'adotante',
    created_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);
