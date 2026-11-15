package com.example.totp.twofactor;

import com.example.totp.user.AppUser;
import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.exceptions.CodeGenerationException;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.recovery.RecoveryCodeGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Iterator;
import java.util.List;

import static dev.samstevens.totp.util.Utils.getDataUriForImage;

/**
 * All TOTP logic lives here. Nothing calls Microsoft: the phone and the server
 * compute the same code from the shared secret and the current time.
 */
@Service
public class TotpService {

    private static final int PERIOD_SECONDS = 30;
    private static final int DIGITS = 6;
    /** Accept the previous and the next 30 s window to tolerate clock drift. */
    private static final int ALLOWED_DRIFT_STEPS = 1;
    private static final int RECOVERY_CODE_COUNT = 10;

    // SHA1 / 6 digits / 30 s is what Microsoft Authenticator (and every other app) supports reliably.
    private final SecretGenerator secretGenerator = new DefaultSecretGenerator(32); // 32 Base32 chars = 160 bits
    private final CodeGenerator codeGenerator = new DefaultCodeGenerator(HashingAlgorithm.SHA1, DIGITS);
    private final QrGenerator qrGenerator = new ZxingPngQrGenerator();
    private final RecoveryCodeGenerator recoveryCodeGenerator = new RecoveryCodeGenerator();

    private final PasswordEncoder passwordEncoder;
    private final String issuer;

    public TotpService(PasswordEncoder passwordEncoder, @Value("${app.totp.issuer}") String issuer) {
        this.passwordEncoder = passwordEncoder;
        this.issuer = issuer;
    }

    public String newSecret() {
        return secretGenerator.generate();
    }

    /** Builds the otpauth:// data that Microsoft Authenticator reads from the QR code. */
    public QrData qrData(String accountName, String secret) {
        return new QrData.Builder()
                .label(accountName)
                .secret(secret)
                .issuer(issuer)
                .algorithm(HashingAlgorithm.SHA1)
                .digits(DIGITS)
                .period(PERIOD_SECONDS)
                .build();
    }

    /** PNG QR code as a data: URI, ready to drop into an <img src="...">. */
    public String qrCodeDataUri(QrData data) {
        try {
            return getDataUriForImage(qrGenerator.generate(data), qrGenerator.getImageMimeType());
        } catch (QrGenerationException e) {
            throw new IllegalStateException("Could not generate QR code", e);
        }
    }

    /**
     * Checks a 6-digit code against the user's secret.
     * On success records the matched time step, so the same code cannot be used twice.
     * The caller must save the user afterwards.
     */
    public boolean verifyCode(AppUser user, String code) {
        if (user.getTotpSecret() == null || code == null || !code.matches("\\d{" + DIGITS + "}")) {
            return false;
        }
        long currentStep = Instant.now().getEpochSecond() / PERIOD_SECONDS;
        long lastUsed = user.getLastTotpTimeStep() == null ? Long.MIN_VALUE : user.getLastTotpTimeStep();

        for (long step = currentStep - ALLOWED_DRIFT_STEPS; step <= currentStep + ALLOWED_DRIFT_STEPS; step++) {
            if (step <= lastUsed) continue; // replay protection
            try {
                String expected = codeGenerator.generate(user.getTotpSecret(), step);
                if (MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                                          code.getBytes(StandardCharsets.UTF_8))) {
                    user.setLastTotpTimeStep(step);
                    return true;
                }
            } catch (CodeGenerationException e) {
                return false;
            }
        }
        return false;
    }

    /** Creates new recovery codes, stores only their hashes, and returns the plain codes to show the user once. */
    public List<String> regenerateRecoveryCodes(AppUser user) {
        String[] codes = recoveryCodeGenerator.generateCodes(RECOVERY_CODE_COUNT);
        user.getRecoveryCodeHashes().clear();
        for (String c : codes) {
            user.getRecoveryCodeHashes().add(passwordEncoder.encode(normalise(c)));
        }
        return List.of(codes);
    }

    /** Uses up a recovery code if it matches one of the stored hashes. The caller must save the user afterwards. */
    public boolean useRecoveryCode(AppUser user, String code) {
        if (code == null || code.isBlank()) return false;
        String candidate = normalise(code);
        Iterator<String> it = user.getRecoveryCodeHashes().iterator();
        while (it.hasNext()) {
            if (passwordEncoder.matches(candidate, it.next())) {
                it.remove(); // one-time use
                return true;
            }
        }
        return false;
    }

    private static String normalise(String code) {
        return code.trim().toLowerCase();
    }
}
