package authserver.service;

public record UserRecord(String sub, String username, String passwordHash, String name,
                         String email, boolean emailVerified, String role) {}
