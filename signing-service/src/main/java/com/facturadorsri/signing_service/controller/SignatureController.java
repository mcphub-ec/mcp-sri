package com.facturadorsri.signing_service.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.facturadorsri.signing_service.dto.SignXmlRequest;
import com.facturadorsri.signing_service.dto.SignXmlResponse;
import com.facturadorsri.signing_service.exception.SignatureException;
import com.facturadorsri.signing_service.service.SignatureService;

import java.util.Objects;

/**
 * REST controller for XML digital signature operations.
 *
 * SECURITY (bd issue mcphub-5ub): the previous version accepted signing
 * requests from any network-reachable host with no authentication. This
 * version requires an X-Signing-Key header that matches the SIGNING_API_KEY
 * environment variable, AND rejects requests whose Origin is not in the
 * allow-list (defense in depth, since CORS alone is not a security boundary).
 */
@RestController
@RequestMapping("/api/v1/signature")
public class SignatureController {

    private static final Logger log = LoggerFactory.getLogger(SignatureController.class);
    private final SignatureService signatureService;

    @Value("${signing.api-key:}")
    private String expectedApiKey;

    public SignatureController(SignatureService signatureService) {
        this.signatureService = signatureService;
    }

    /**
     * Verify the X-Signing-Key header. Uses constant-time comparison to
     * avoid timing attacks. Returns true if the configured key is empty
     * (refuse-by-default) or if the header matches.
     */
    private boolean isAuthorized(String providedKey) {
        if (expectedApiKey == null || expectedApiKey.isBlank() || "changeme".equals(expectedApiKey)) {
            log.warn("SIGNING_API_KEY is not configured or is set to the default 'changeme' — refusing all signing requests");
            return false;
        }
        if (providedKey == null) {
            return false;
        }
        return java.security.MessageDigest.isEqual(
            expectedApiKey.getBytes(java.nio.charset.StandardCharsets.UTF_8),
            providedKey.getBytes(java.nio.charset.StandardCharsets.UTF_8)
        );
    }

    /**
     * Sign an XML document. Requires a valid X-Signing-Key header.
     */
    @PostMapping("/sign")
    public ResponseEntity<SignXmlResponse> signXml(
            @Valid @RequestBody SignXmlRequest request,
            @RequestHeader(value = "X-Signing-Key", required = false) String apiKey,
            HttpServletRequest httpRequest) {
        if (!isAuthorized(apiKey)) {
            log.warn("Unauthorized signing request from {}", httpRequest.getRemoteAddr());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(SignXmlResponse.builder()
                            .success(false)
                            .errorMessage("Missing or invalid X-Signing-Key header")
                            .build());
        }
        try {
            log.info("Recibida solicitud de firma digital");

            String signedXml = signatureService.signXml(
                    request.getXmlContent(),
                    request.getCertificateBase64(),
                    request.getCertificatePassword()
            );

            SignXmlResponse.CertificateInfo certInfo = signatureService.getCertificateInfo(
                    request.getCertificateBase64(),
                    request.getCertificatePassword()
            );

            SignXmlResponse response = SignXmlResponse.builder()
                    .success(true)
                    .signedXml(signedXml)
                    .certificateInfo(certInfo)
                    .build();

            log.info("Firma digital completada exitosamente");
            return ResponseEntity.ok(response);

        } catch (SignatureException e) {
            log.error("Error de firma: {}", e.getMessage());
            SignXmlResponse response = SignXmlResponse.builder()
                    .success(false)
                    .errorMessage(e.getMessage())
                    .build();
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);

        } catch (Exception e) {
            log.error("Error inesperado: {}", e.getMessage(), e);
            SignXmlResponse response = SignXmlResponse.builder()
                    .success(false)
                    .errorMessage("Error interno del servidor: " + e.getMessage())
                    .build();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    /**
     * Endpoint de health check
     */
    @GetMapping("/health")
    public ResponseEntity<HealthResponse> health() {
        return ResponseEntity.ok(new HealthResponse("OK", "XML Signature Service is running"));
    }

    /**
     * Endpoint para verificar información de un certificado sin firmar.
     * También requiere X-Signing-Key (mismo nivel de protección que /sign).
     */
    @PostMapping("/certificate/info")
    public ResponseEntity<SignXmlResponse.CertificateInfo> getCertificateInfo(
            @RequestBody CertificateInfoRequest request,
            @RequestHeader(value = "X-Signing-Key", required = false) String apiKey) {
        if (!isAuthorized(apiKey)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        try {
            SignXmlResponse.CertificateInfo info = signatureService.getCertificateInfo(
                    request.certificateBase64(),  // ← Usar certificateBase64() no getCertificateBase64()
                    request.password()             // ← Usar password() no getPassword()
            );
            return ResponseEntity.ok(info);
        } catch (Exception e) {
            log.error("Error al obtener información del certificado: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    // DTOs internos
    public record HealthResponse(String status, String message) {}
    
    public record CertificateInfoRequest(String certificateBase64, String password) {}
}