package com.example.totp.user;

import com.example.totp.crypto.SecretEncryptor;
import jakarta.persistence.*;

import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "app_user")
public class AppUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String passwordHash;

    /** Base32 TOTP secret, AES-GCM encrypted in the database. Null until the user starts setup. */
    @Convert(converter = SecretEncryptor.class)
    @Column(length = 512)
    private String totpSecret;

    /** True only after the user has proven the authenticator app works by entering a valid code. */
    private boolean totpEnabled;

    /** Last 30-second time step that was accepted. Codes from this step or earlier are rejected (replay protection). */
    private Long lastTotpTimeStep;

    /** BCrypt hashes of unused one-time recovery codes. */
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "recovery_code", joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "code_hash")
    private Set<String> recoveryCodeHashes = new HashSet<>();

    protected AppUser() { }

    public AppUser(String username, String passwordHash) {
        this.username = username;
        this.passwordHash = passwordHash;
    }

    public Long getId() { return id; }
    public String getUsername() { return username; }
    public String getPasswordHash() { return passwordHash; }
    public String getTotpSecret() { return totpSecret; }
    public void setTotpSecret(String totpSecret) { this.totpSecret = totpSecret; }
    public boolean isTotpEnabled() { return totpEnabled; }
    public void setTotpEnabled(boolean totpEnabled) { this.totpEnabled = totpEnabled; }
    public Long getLastTotpTimeStep() { return lastTotpTimeStep; }
    public void setLastTotpTimeStep(Long lastTotpTimeStep) { this.lastTotpTimeStep = lastTotpTimeStep; }
    public Set<String> getRecoveryCodeHashes() { return recoveryCodeHashes; }
}
