package com.example.totp.web;

import com.example.totp.twofactor.TotpService;
import com.example.totp.user.AppUser;
import com.example.totp.user.UserRepository;
import dev.samstevens.totp.qr.QrData;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.security.Principal;
import java.util.List;
import java.util.Map;

/**
 * Endpoints for a logged-in user to turn 2FA on and off.
 *   POST /api/2fa/setup   -> new secret + QR code (2FA not active yet)
 *   POST /api/2fa/enable  -> confirm with a code from the app; returns recovery codes once
 *   POST /api/2fa/disable -> requires a current code
 */
@RestController
@RequestMapping("/api")
public class TwoFactorController {

    private final UserRepository users;
    private final TotpService totp;

    public TwoFactorController(UserRepository users, TotpService totp) {
        this.users = users;
        this.totp = totp;
    }

    public record CodeRequest(@NotBlank String code) { }

    @GetMapping("/me")
    public Map<String, Object> me(Principal principal) {
        AppUser user = current(principal);
        return Map.of("username", user.getUsername(), "totpEnabled", user.isTotpEnabled(),
                      "recoveryCodesLeft", user.getRecoveryCodeHashes().size());
    }

    @PostMapping("/2fa/setup")
    @Transactional
    public Map<String, Object> setup(Principal principal) {
        AppUser user = current(principal);
        if (user.isTotpEnabled()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "2FA is already enabled");
        }
        String secret = totp.newSecret();
        user.setTotpSecret(secret);   // stored encrypted, but NOT active until /enable succeeds
        user.setLastTotpTimeStep(null);
        users.save(user);

        QrData data = totp.qrData(user.getUsername(), secret);
        return Map.of(
                "qrCode", totp.qrCodeDataUri(data), // data:image/png;base64,...  -> <img src>
                "secret", secret,                   // for "enter code manually" in the app
                "otpauthUri", data.getUri());
    }

    @PostMapping("/2fa/enable")
    @Transactional
    public Map<String, Object> enable(@Valid @RequestBody CodeRequest body, Principal principal) {
        AppUser user = current(principal);
        if (user.isTotpEnabled()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "2FA is already enabled");
        }
        if (user.getTotpSecret() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Call /api/2fa/setup first");
        }
        if (!totp.verifyCode(user, body.code().replace(" ", ""))) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid code. Check the phone's time is set automatically.");
        }
        user.setTotpEnabled(true);
        List<String> recoveryCodes = totp.regenerateRecoveryCodes(user);
        users.save(user);
        return Map.of("enabled", true, "recoveryCodes", recoveryCodes); // shown ONCE; only hashes are kept
    }

    @PostMapping("/2fa/disable")
    @Transactional
    public Map<String, Object> disable(@Valid @RequestBody CodeRequest body, Principal principal) {
        AppUser user = current(principal);
        if (!user.isTotpEnabled()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "2FA is not enabled");
        }
        if (!totp.verifyCode(user, body.code().replace(" ", ""))) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid code");
        }
        user.setTotpEnabled(false);
        user.setTotpSecret(null);
        user.setLastTotpTimeStep(null);
        user.getRecoveryCodeHashes().clear();
        users.save(user);
        return Map.of("enabled", false);
    }

    private AppUser current(Principal principal) {
        return users.findByUsername(principal.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED));
    }
}
