package com.example.totp.web;

import com.example.totp.twofactor.TotpService;
import com.example.totp.user.AppUser;
import com.example.totp.user.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Two-step login:
 *   1) POST /api/auth/login        username + password  -> either logged in, or {"mfaRequired": true}
 *   2) POST /api/auth/login/verify 6-digit code (or a recovery code) -> logged in
 * Between the two steps the user is only "pre-authenticated": the user id is kept in the session,
 * but no Spring Security authentication exists yet, so protected endpoints stay closed.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final String PRE_AUTH_USER_ID = "PRE_AUTH_USER_ID";
    private static final String PRE_AUTH_STARTED = "PRE_AUTH_STARTED";
    private static final String PRE_AUTH_ATTEMPTS = "PRE_AUTH_ATTEMPTS";
    private static final long PRE_AUTH_TTL_SECONDS = 300;
    private static final int MAX_CODE_ATTEMPTS = 5;

    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final TotpService totp;
    private final SecurityContextRepository securityContextRepository;

    public AuthController(UserRepository users, PasswordEncoder passwordEncoder,
                          TotpService totp, SecurityContextRepository securityContextRepository) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.totp = totp;
        this.securityContextRepository = securityContextRepository;
    }

    public record Credentials(@NotBlank String username, @NotBlank @Size(min = 8) String password) { }
    public record CodeRequest(@NotBlank String code) { }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public Map<String, Object> register(@Valid @RequestBody Credentials body) {
        if (users.existsByUsername(body.username())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Username taken");
        }
        users.save(new AppUser(body.username(), passwordEncoder.encode(body.password())));
        return Map.of("registered", true);
    }

    @PostMapping("/login")
    public Map<String, Object> login(@Valid @RequestBody Credentials body,
                                     HttpServletRequest request, HttpServletResponse response) {
        AppUser user = users.findByUsername(body.username())
                .filter(u -> passwordEncoder.matches(body.password(), u.getPasswordHash()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Bad credentials"));

        if (!user.isTotpEnabled()) {
            signIn(user, request, response);
            return Map.of("mfaRequired", false, "username", user.getUsername());
        }

        // Password OK, but 2FA is on: remember who they are and wait for the code.
        HttpSession session = request.getSession(true);
        request.changeSessionId(); // defend against session fixation
        session.setAttribute(PRE_AUTH_USER_ID, user.getId());
        session.setAttribute(PRE_AUTH_STARTED, Instant.now().getEpochSecond());
        session.setAttribute(PRE_AUTH_ATTEMPTS, 0);
        return Map.of("mfaRequired", true);
    }

    @PostMapping("/login/verify")
    @Transactional
    public Map<String, Object> verify(@Valid @RequestBody CodeRequest body,
                                      HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute(PRE_AUTH_USER_ID) == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Log in with your password first");
        }

        long started = (Long) session.getAttribute(PRE_AUTH_STARTED);
        int attempts = (Integer) session.getAttribute(PRE_AUTH_ATTEMPTS);
        if (Instant.now().getEpochSecond() - started > PRE_AUTH_TTL_SECONDS || attempts >= MAX_CODE_ATTEMPTS) {
            clearPreAuth(session);
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Login expired or too many attempts. Start again.");
        }
        session.setAttribute(PRE_AUTH_ATTEMPTS, attempts + 1);

        AppUser user = users.findById((Long) session.getAttribute(PRE_AUTH_USER_ID))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED));

        String code = body.code().replace(" ", "");
        boolean ok = totp.verifyCode(user, code) || totp.useRecoveryCode(user, body.code());
        if (!ok) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid code");
        }
        users.save(user); // persists lastTotpTimeStep / consumed recovery code

        clearPreAuth(session);
        signIn(user, request, response);
        return Map.of("loggedIn", true, "username", user.getUsername(),
                      "recoveryCodesLeft", user.getRecoveryCodeHashes().size());
    }

    private void signIn(AppUser user, HttpServletRequest request, HttpServletResponse response) {
        request.getSession(true);
        request.changeSessionId();
        var auth = new UsernamePasswordAuthenticationToken(
                user.getUsername(), null, List.of(new SimpleGrantedAuthority("ROLE_USER")));
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(auth);
        SecurityContextHolder.setContext(context);
        securityContextRepository.saveContext(context, request, response);
    }

    private static void clearPreAuth(HttpSession session) {
        session.removeAttribute(PRE_AUTH_USER_ID);
        session.removeAttribute(PRE_AUTH_STARTED);
        session.removeAttribute(PRE_AUTH_ATTEMPTS);
    }
}
