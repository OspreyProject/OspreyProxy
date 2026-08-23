/*
 * Copyright (C) 2024-2026 Osprey Project LLC and contributors (https://osprey.ac)
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
package net.foulest.ospreyproxy;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import jakarta.mail.internet.MimeMessage;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import net.foulest.ospreyproxy.util.JacksonUtil;
import net.foulest.ospreyproxy.util.RequestUtil;
import org.jetbrains.annotations.Unmodifiable;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;

/**
 * The public contact form behind osprey.ac/contact. The website page posts here cross-origin from
 * the same single origin /check allows, protected by the same Cloudflare Turnstile site key and
 * secret. Nothing reaches the support inbox until the sender proves they own their address by
 * opening the link emailed to them, which keeps the inbox free of spoofed and throwaway senders.
 * <p>
 * Flow: {@code POST /contact/submit} validates, verifies the captcha, stores the message in the
 * scan store database with a hashed single-use token, and emails the verification link.
 * {@code POST /contact/verify} consumes the token, marks the submission verified, and forwards it
 * to the support address with the sender set as Reply-To. Unverified submissions expire after 24
 * hours and are pruned hourly; forwarded submissions are kept for a week and then pruned too,
 * since the email is the record.
 * <p>
 * Off by default and of no use to a self-hoster: it requires the scan store and a configured
 * {@code spring.mail} transport, and every response carries a human-readable error the page shows
 * inline.
 */
@Slf4j
@RestController
@ConditionalOnProperty(name = "osprey.contact.enabled", havingValue = "true")
public class ContactHandler {

    private static final String CONTEXT = "contact";
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[\\w\\-.]+@([\\w-]+\\.)+[\\w-]{2,}$");
    private static final Pattern TOKEN_PATTERN = Pattern.compile("[A-Za-z0-9_-]{40,64}");
    private static final Pattern LINE_CONTROL_PATTERN = Pattern.compile("\\p{Cntrl}");
    private static final Pattern BLOCK_CONTROL_PATTERN = Pattern.compile("[\\p{Cntrl}&&[^\\n\\r\\t]]");
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final int MAX_NAME_LENGTH = 120;
    private static final int MAX_EMAIL_LENGTH = 200;
    private static final int MAX_COMPANY_LENGTH = 160;
    private static final int MAX_MESSAGE_LENGTH = 4000;
    private static final int MIN_MESSAGE_LENGTH = 10;
    private static final int MAX_CAPTCHA_LENGTH = 2048;

    private static final long VERIFY_TTL_MILLIS = 24L * 60L * 60_000L;
    private static final long KEEP_VERIFIED_MILLIS = 7L * 24L * 60L * 60_000L;
    private static final String HEADER_BG = "#1B2733";
    private static final String ACCENT = "#835AEA";

    /**
     * The categories the form offers, keyed by the value the page submits. The server accepts
     * nothing outside this map so the subject line is never sender-controlled prose.
     */
    private static final Map<String, String> CATEGORIES = categories();

    /**
     * The categories that require a company or MSP name.
     */
    private static final List<String> COMPANY_REQUIRED = List.of("business", "msp", "partnership");

    private final JdbcTemplate jdbc;
    private final @Nullable JavaMailSender sender;
    private final String fromAddress;
    private final String supportAddress;
    private final String siteOrigin;

    private final boolean turnstileEnabled;
    private final String turnstileSecret;
    private final String turnstileVerifyUrl;
    private final HttpClient turnstileClient;

    private final Bandwidth submitBandwidth;

    private final Cache<String, Bucket> submitBuckets = Caffeine.newBuilder()
            .expireAfterAccess(Duration.ofHours(1))
            .maximumSize(20_000)
            .build();

    private final ExecutorService mailExecutor = Executors.newSingleThreadExecutor(r -> {
        Thread thread = new Thread(r, "contact-mail");
        thread.setDaemon(true);
        return thread;
    });

    /**
     * Constructs the handler, creating its table in the scan store database.
     *
     * @param scanJdbcTemplate The scan store database the submissions are kept in.
     * @param senderProvider The mail transport, present only when spring.mail is configured.
     * @param fromAddress The From address verification and forwarded mail is sent from.
     * @param supportAddress The inbox verified submissions are forwarded to.
     * @param siteOrigin The website origin the verification link points back to.
     * @param turnstileEnabled Whether captcha verification is enforced.
     * @param turnstileSecret The Cloudflare Turnstile secret key.
     * @param turnstileVerifyUrl The Turnstile siteverify URL.
     * @param turnstileTimeoutSeconds The Turnstile verification request timeout, in seconds.
     * @param submitCapacity Submissions allowed per IP per window.
     * @param submitWindowSeconds The submission rate window, in seconds.
     */
    public ContactHandler(@NonNull JdbcTemplate scanJdbcTemplate,
                          @NonNull ObjectProvider<JavaMailSender> senderProvider,
                          @Value("${osprey.contact.from:support@osprey.ac}") String fromAddress,
                          @Value("${osprey.contact.to:support@osprey.ac}") String supportAddress,
                          @Value("${osprey.check.allowed-origin:https://osprey.ac}") String siteOrigin,
                          @Value("${osprey.check.turnstile.enabled:false}") boolean turnstileEnabled,
                          @Value("${osprey.check.turnstile.secret:}") String turnstileSecret,
                          @Value("${osprey.check.turnstile.verify-url:https://challenges.cloudflare.com/turnstile/v0/siteverify}") String turnstileVerifyUrl,
                          @Value("${osprey.check.turnstile.timeout-seconds:5}") long turnstileTimeoutSeconds,
                          @Value("${osprey.contact.rate.capacity:5}") long submitCapacity,
                          @Value("${osprey.contact.rate.window-seconds:900}") long submitWindowSeconds) {
        jdbc = scanJdbcTemplate;
        sender = senderProvider.getIfAvailable();
        this.fromAddress = fromAddress.strip();
        this.supportAddress = supportAddress.strip();
        this.siteOrigin = siteOrigin.replaceAll("/+$", "");

        this.turnstileEnabled = turnstileEnabled;
        this.turnstileSecret = turnstileSecret;
        this.turnstileVerifyUrl = turnstileVerifyUrl;

        turnstileClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(turnstileTimeoutSeconds))
                .build();

        submitBandwidth = Bandwidth.builder()
                .capacity(submitCapacity)
                .refillGreedy(submitCapacity, Duration.ofSeconds(submitWindowSeconds))
                .build();

        jdbc.execute("""
                CREATE TABLE IF NOT EXISTS contact_submissions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_hash TEXT NOT NULL DEFAULT '',
                    category TEXT NOT NULL,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL,
                    company TEXT NOT NULL DEFAULT '',
                    message TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    verified_at INTEGER NOT NULL DEFAULT 0
                )""");

        jdbc.execute("CREATE INDEX IF NOT EXISTS idx_contact_token ON contact_submissions(token_hash)");

        if (sender == null) {
            log.warn("[contact] No spring.mail transport is configured; every submission will be rejected");
        }
    }

    /**
     * Accepts a contact form submission, verifies the captcha, and emails the sender a verification
     * link.
     *
     * @param body The JSON body: category, name, email, company, message, token.
     * @param request The incoming servlet request, used for IP extraction and captcha remote IP.
     * @return {@code {"ok": true}} or an error with a message.
     */
    @PostMapping(value = "/contact/submit", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> submit(@RequestBody(required = false) @Nullable Map<String, Object> body,
                                                      @NonNull HttpServletRequest request) {
        Map<String, Object> fields = body == null ? Map.of() : body;

        String category = cleanLine(fields.get("category"), 40);
        String name = cleanLine(fields.get("name"), MAX_NAME_LENGTH);
        String email = cleanLine(fields.get("email"), MAX_EMAIL_LENGTH).toLowerCase();
        String company = cleanLine(fields.get("company"), MAX_COMPANY_LENGTH);
        String message = cleanBlock(fields.get("message"), MAX_MESSAGE_LENGTH);
        String captcha = cleanLine(fields.get("token"), MAX_CAPTCHA_LENGTH);

        String error = validate(category, name, email, company, message);

        if (error != null) {
            return error(400, error);
        }

        String hashedIp = RequestUtil.hashClientIp(request, CONTEXT);
        Bucket bucket = submitBuckets.get(hashedIp, ignored -> Bucket.builder().addLimit(submitBandwidth).build());

        if (!bucket.tryConsume(1)) {
            return error(429, "Too many messages from your network right now. Please try again later.");
        }

        if (!verifyTurnstile(captcha, request)) {
            return error(403, "The captcha could not be verified. Please try again.");
        }

        if (sender == null) {
            return error(503, "Email delivery is not available right now. Please email " + supportAddress + " directly.");
        }

        long now = System.currentTimeMillis();
        String token = randomToken();

        jdbc.update("""
                        INSERT INTO contact_submissions
                            (token_hash, category, name, email, company, message, created_at, expires_at, verified_at)
                        VALUES (?,?,?,?,?,?,?,?,0)""",
                sha256(token), category, name, email, company, message, now, now + VERIFY_TTL_MILLIS
        );

        mailExecutor.execute(() -> sendVerificationEmail(email, name, token));
        return ResponseEntity.ok(Map.of("ok", true));
    }

    /**
     * Consumes a verification token, marks the submission verified, and forwards it to the support
     * inbox. A token that is unknown, expired, or already used returns the same error.
     *
     * @param body The JSON body: token.
     * @return {@code {"ok": true}} or an error with a message.
     */
    @PostMapping(value = "/contact/verify", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> verify(@RequestBody(required = false) @Nullable Map<String, Object> body) {
        String token = cleanLine(body == null ? null : body.get("token"), 64);
        String invalid = "This verification link is invalid or has expired. Please send your message again.";

        if (!TOKEN_PATTERN.matcher(token).matches()) {
            return error(400, invalid);
        }

        long now = System.currentTimeMillis();

        List<Map<String, Object>> rows = jdbc.queryForList("""
                        SELECT id, category, name, email, company, message, created_at FROM contact_submissions
                        WHERE token_hash = ? AND verified_at = 0 AND expires_at > ?""",
                sha256(token), now
        );

        if (rows.isEmpty()) {
            return error(400, invalid);
        }

        Map<String, Object> row = rows.getFirst();
        long id = ((Number) row.get("id")).longValue();

        // The token hash is cleared with the verified stamp so the link can never be replayed.
        int updated = jdbc.update(
                "UPDATE contact_submissions SET verified_at = ?, token_hash = '' WHERE id = ? AND verified_at = 0", now, id
        );

        if (updated != 1) {
            return error(400, invalid);
        }

        String category = String.valueOf(row.get("category"));
        String name = String.valueOf(row.get("name"));
        String email = String.valueOf(row.get("email"));
        String company = String.valueOf(row.get("company"));
        String message = String.valueOf(row.get("message"));
        long createdAt = row.get("created_at") instanceof Number n ? n.longValue() : now;

        mailExecutor.execute(() -> forwardToSupport(category, name, email, company, message, createdAt));
        return ResponseEntity.ok(Map.of("ok", true));
    }

    /**
     * Hourly: drops unverified submissions past their link window and forwarded submissions older
     * than a week.
     */
    @Scheduled(fixedDelay = 3_600_000L, initialDelay = 600_000L)
    public void prune() {
        long now = System.currentTimeMillis();

        int expired = jdbc.update("DELETE FROM contact_submissions WHERE verified_at = 0 AND expires_at < ?", now);

        int forwarded = jdbc.update("DELETE FROM contact_submissions WHERE verified_at > 0 AND verified_at < ?",
                now - KEEP_VERIFIED_MILLIS
        );

        if (expired + forwarded > 0) {
            log.info("[contact] Pruned {} expired and {} forwarded submissions", expired, forwarded);
        }
    }

    /**
     * Verifies a Turnstile token with Cloudflare, exactly as /check does. A blank secret with
     * Turnstile enabled fails closed.
     *
     * @param token The widget response token.
     * @param request The incoming request, for the remote IP hint.
     * @return true when the captcha passed or verification is disabled.
     */
    private boolean verifyTurnstile(@NonNull String token, @NonNull HttpServletRequest request) {
        if (!turnstileEnabled) {
            return true;
        }

        if (turnstileSecret.isBlank() || token.isBlank()) {
            return false;
        }

        try {
            StringBuilder form = new StringBuilder(256)
                    .append("secret=").append(URLEncoder.encode(turnstileSecret, StandardCharsets.UTF_8))
                    .append("&response=").append(URLEncoder.encode(token, StandardCharsets.UTF_8));

            String remoteIp = request.getHeader("X-Real-IP");

            if (remoteIp != null && remoteIp.length() <= 45) {
                String stripped = remoteIp.strip();

                if (isIpLiteral(stripped)) {
                    form.append("&remoteip=").append(URLEncoder.encode(stripped, StandardCharsets.UTF_8));
                }
            }

            HttpRequest httpRequest = HttpRequest.newBuilder()
                    .uri(URI.create(turnstileVerifyUrl))
                    .timeout(Duration.ofSeconds(5))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(form.toString()))
                    .build();

            HttpResponse<String> response = turnstileClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                log.warn("[contact] Turnstile verify returned HTTP {}", response.statusCode());
                return false;
            }

            Map<String, Object> parsed = JacksonUtil.MAPPER.readValue(response.body(), JacksonUtil.MAP_TYPE_OBJECT);
            return Boolean.TRUE.equals(parsed.get("success"));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[contact] Turnstile verification error: {}", e.getClass().getName());
            return false;
        }
    }

    /**
     * Emails the verification link to the sender, laid out like the console's account emails.
     *
     * @param to The sender's address.
     * @param name The sender's name, for the greeting.
     * @param token The raw verification token to embed in the link.
     */
    private void sendVerificationEmail(@NonNull String to, @NonNull String name, @NonNull String token) {
        if (sender == null) {
            return;
        }

        try {
            String link = siteOrigin + "/contact/?verify=" + token;

            String html = shell("Confirm your message",
                    "<p style=\"margin:0 0 12px;color:#3d4a57;font-size:14px;line-height:1.6;\">Hi " + esc(name) + ",</p>"
                            + "<p style=\"margin:0 0 24px;color:#3d4a57;font-size:14px;line-height:1.6;\">You sent a message to Osprey through osprey.ac/contact. Confirm this email address and it will be delivered to our team. The link below is valid for 24 hours.</p>"
                            + "<a href=\"" + esc(link) + "\" style=\"display:inline-block;background:" + ACCENT + ";color:#ffffff;text-decoration:none;font-size:14px;font-weight:bold;padding:12px 24px;border-radius:6px;\">Confirm and send</a>",
                    "If you did not send this, you can ignore this email; the message is discarded unless confirmed."
            );

            MimeMessage mime = sender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mime, true, "UTF-8");
            helper.setFrom(fromAddress, "Osprey");
            helper.setTo(to);
            helper.setSubject("[Osprey] Confirm your message");
            helper.setText("Hi " + name + ",\n\n"
                    + "You sent a message to Osprey through osprey.ac/contact. Open this link within 24 hours "
                    + "to confirm this email address and deliver it to our team:\n"
                    + link + "\n\n"
                    + "If you did not send this, you can ignore this email; the message is discarded unless confirmed.", html);
            sender.send(mime);
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[contact] Verification email delivery failed: {}", e.getClass().getName());
        }
    }

    /**
     * Forwards a verified submission to the support inbox with the sender as Reply-To.
     *
     * @param category The submitted category key.
     * @param name The sender's name.
     * @param email The sender's verified address.
     * @param company The sender's company, possibly empty.
     * @param message The message body.
     * @param createdAt When the form was submitted.
     */
    private void forwardToSupport(@NonNull String category, @NonNull String name, @NonNull String email,
                                  @NonNull String company, @NonNull String message, long createdAt) {
        if (sender == null) {
            return;
        }

        String label = CATEGORIES.getOrDefault(category, "General inquiry");

        try {
            String details = detailRow("Category", esc(label))
                    + detailRow("Name", esc(name))
                    + detailRow("Email", "<a href=\"mailto:" + esc(email) + "\" style=\"color:#1b2733;\">" + esc(email) + "</a>")
                    + (company.isEmpty() ? "" : detailRow("Company", esc(company)))
                    + detailRow("Submitted", esc(Instant.ofEpochMilli(createdAt).toString()));

            String safeMessage = esc(message).replace("\r\n", "\n").replace("\n", "<br>");

            String html = shell(label,
                    "<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" style=\"margin:0 0 16px;\">" + details + "</table>"
                            + "<p style=\"margin:0;padding:14px 16px;background:#f9fafb;border:1px solid #e2e4e8;border-radius:6px;color:#3d4a57;font-size:14px;line-height:1.6;\">" + safeMessage + "</p>",
                    "Sent through osprey.ac/contact. The sender's email address was verified before delivery. Reply to this email to respond directly."
            );

            MimeMessage mime = sender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mime, true, "UTF-8");
            helper.setFrom(fromAddress, "Osprey Contact Form");
            helper.setTo(supportAddress);
            helper.setReplyTo(email, name);
            helper.setSubject("[Contact] " + label + ": " + name);
            helper.setText("Category: " + label + "\n"
                    + "Name: " + name + "\n"
                    + "Email: " + email + "\n"
                    + (company.isEmpty() ? "" : ("Company: " + company + "\n"))
                    + "Submitted: " + Instant.ofEpochMilli(createdAt) + "\n\n"
                    + message, html);
            sender.send(mime);
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[contact] Forwarding to the support inbox failed: {}", e.getClass().getName());
        }
    }

    /**
     * Wraps email content in the console email layout: dark header with the Osprey wordmark, an
     * accent stripe, the body, and a muted footer note.
     *
     * @param title The already-escaped heading.
     * @param content The body HTML.
     * @param footer The plain footer note.
     * @return The full HTML document.
     */
    private static @NonNull String shell(@NonNull String title, @NonNull String content, @NonNull String footer) {
        return "<!DOCTYPE html><html><body style=\"margin:0;padding:0;background:#f4f5f7;font-family:Arial,Helvetica,sans-serif;\">"
                + "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"background:#f4f5f7;padding:24px 0;\"><tr><td align=\"center\">"
                + "<table role=\"presentation\" width=\"560\" cellpadding=\"0\" cellspacing=\"0\" style=\"background:#ffffff;border-radius:8px;overflow:hidden;border:1px solid #e2e4e8;\">"
                + "<tr><td style=\"background:" + HEADER_BG + ";padding:20px 28px;\"><span style=\"color:#ffffff;font-size:18px;font-weight:bold;letter-spacing:0.5px;vertical-align:middle;\">Osprey</span></td></tr>"
                + "<tr><td style=\"border-top:4px solid " + ACCENT + ";\"></td></tr>"
                + "<tr><td style=\"padding:28px;\"><h2 style=\"margin:0 0 12px;color:#1b2733;font-size:20px;\">" + esc(title) + "</h2>" + content + "</td></tr>"
                + "<tr><td style=\"padding:16px 28px;background:#f9fafb;border-top:1px solid #e2e4e8;\"><p style=\"margin:0;color:#8b95a1;font-size:12px;\">" + esc(footer) + "</p></td></tr>"
                + "</table></td></tr></table></body></html>";
    }

    /**
     * Renders one label and value row of the forwarded message's detail table.
     *
     * @param label The row label.
     * @param value The already-escaped value HTML.
     * @return The row HTML.
     */
    private static @NonNull String detailRow(@NonNull String label, @NonNull String value) {
        return "<tr><td style=\"padding:6px 12px 6px 0;color:#8b95a1;font-size:13px;white-space:nowrap;\">" + label
                + "</td><td style=\"padding:6px 0;color:#1b2733;font-size:13px;\">" + value + "</td></tr>";
    }

    /**
     * Validates the submitted fields, returning a human-readable error or null when acceptable.
     *
     * @param category The category key.
     * @param name The sender's name.
     * @param email The sender's address.
     * @param company The sender's company, required for the business categories.
     * @param message The message body.
     * @return The error message, or null.
     */
    private static @Nullable String validate(@NonNull String category, @NonNull String name,
                                             @NonNull String email, @NonNull String company,
                                             @NonNull String message) {
        if (!CATEGORIES.containsKey(category)) {
            return "Please pick what your message is about.";
        }

        if (name.isEmpty()) {
            return "Your name is required.";
        }

        if (email.isEmpty() || !EMAIL_PATTERN.matcher(email).matches()) {
            return "A valid email address is required so we can reply to you.";
        }

        if (COMPANY_REQUIRED.contains(category) && company.isEmpty()) {
            return "Your company or MSP name is required for this type of inquiry.";
        }

        if (message.length() < MIN_MESSAGE_LENGTH) {
            return "Please write a little more detail in your message.";
        }
        return null;
    }

    /**
     * Builds a JSON error response carrying a message the page shows inline.
     *
     * @param status The HTTP status.
     * @param message The message.
     * @return The response.
     */
    private static @NonNull ResponseEntity<Map<String, Object>> error(int status, @NonNull String message) {
        return ResponseEntity.status(status).contentType(MediaType.APPLICATION_JSON).body(Map.of("error", message));
    }

    /**
     * Builds the ordered category map the form and the subject lines share.
     *
     * @return The category keys and labels.
     */
    private static @NonNull @Unmodifiable Map<String, String> categories() {
        Map<String, String> map = new LinkedHashMap<>();
        map.put("business", "Business inquiry");
        map.put("msp", "MSP partnership");
        map.put("provider", "Provider or integration");
        map.put("partnership", "Other business opportunity");
        map.put("support", "Support or false positive");
        map.put("general", "General inquiry");
        return Map.copyOf(map);
    }

    /**
     * Normalizes a single-line field: control characters become spaces, whitespace is trimmed,
     * and the value is truncated to the cap.
     *
     * @param value The raw value, possibly null or non-string.
     * @param maxLength The cap.
     * @return The cleaned value.
     */
    private static @NonNull String cleanLine(@Nullable Object value, int maxLength) {
        String text = value == null ? "" : String.valueOf(value);
        String out = LINE_CONTROL_PATTERN.matcher(text).replaceAll(" ").strip();
        return out.length() > maxLength ? out.substring(0, maxLength) : out;
    }

    /**
     * Normalizes the message body: line breaks and tabs survive, other control characters become
     * spaces, and the value is truncated to the cap.
     *
     * @param value The raw value, possibly null or non-string.
     * @param maxLength The cap.
     * @return The cleaned value.
     */
    private static @NonNull String cleanBlock(@Nullable Object value, int maxLength) {
        String text = value == null ? "" : String.valueOf(value);
        String out = BLOCK_CONTROL_PATTERN.matcher(text).replaceAll(" ").strip();
        return out.length() > maxLength ? out.substring(0, maxLength) : out;
    }

    /**
     * Whether the value contains only characters valid in an IPv4 or IPv6 literal, matching the
     * shape check /check applies before forwarding the client hint to Turnstile.
     *
     * @param value The candidate value.
     * @return {@code true} if every character is a hex digit, dot, or colon.
     */
    private static boolean isIpLiteral(@NonNull String value) {
        if (value.isEmpty()) {
            return false;
        }

        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            boolean ok = (c >= '0' && c <= '9')
                    || (c >= 'a' && c <= 'f')
                    || (c >= 'A' && c <= 'F')
                    || c == '.' || c == ':';

            if (!ok) {
                return false;
            }
        }
        return true;
    }

    /**
     * Escapes a value for safe interpolation into HTML.
     *
     * @param value The raw value.
     * @return The escaped value.
     */
    private static @NonNull String esc(@NonNull String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    /**
     * Generates a 32-byte URL-safe random token.
     *
     * @return The token.
     */
    private static @NonNull String randomToken() {
        byte[] buf = new byte[32];
        RANDOM.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    /**
     * Computes the lowercase hex SHA-256 of a string.
     *
     * @param value The value.
     * @return The hash.
     */
    private static @NonNull String sha256(@NonNull String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
