import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class JWKSServer {

    private static final String DB_FILE = "totally_not_my_privateKeys.db";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static Connection dbConnection;

    public static void main(String[] args) throws Exception {
        initializeDatabase();
        ensureSeedKeys();

        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/.well-known/jwks.json", new JWKSHandler());
        server.createContext("/auth", new AuthHandler());
        server.setExecutor(null);
        server.start();

        System.out.println("JWKS server started on http://localhost:8080");
    }

    private static void initializeDatabase() throws SQLException {
        dbConnection = DriverManager.getConnection("jdbc:sqlite:" + DB_FILE);

        try (Statement statement = dbConnection.createStatement()) {
            statement.executeUpdate(
                    "CREATE TABLE IF NOT EXISTS keys (" +
                            "kid INTEGER PRIMARY KEY AUTOINCREMENT, " +
                            "key BLOB NOT NULL, " +
                            "exp INTEGER NOT NULL)"
            );
        }
    }

    private static void ensureSeedKeys() throws Exception {
        if (!hasKeyForExpiredStatus(true)) {
            insertNewKey(true);
        }

        if (!hasKeyForExpiredStatus(false)) {
            insertNewKey(false);
        }
    }

    private static boolean hasKeyForExpiredStatus(boolean expired) throws SQLException {
        long now = Instant.now().getEpochSecond();
        String sql = expired
                ? "SELECT 1 FROM keys WHERE exp <= ? LIMIT 1"
                : "SELECT 1 FROM keys WHERE exp > ? LIMIT 1";

        try (PreparedStatement preparedStatement = dbConnection.prepareStatement(sql)) {
            preparedStatement.setLong(1, now);
            try (ResultSet rs = preparedStatement.executeQuery()) {
                return rs.next();
            }
        }
    }

    private static void insertNewKey(boolean expired) throws Exception {
        KeyPair keyPair = generateRsaKeyPair();
        long exp = expired
                ? Instant.now().minusSeconds(3600).getEpochSecond()
                : Instant.now().plusSeconds(3600).getEpochSecond();

        String sql = "INSERT INTO keys (key, exp) VALUES (?, ?)";
        try (PreparedStatement ps = dbConnection.prepareStatement(sql)) {
            ps.setBytes(1, keyPair.getPrivate().getEncoded());
            ps.setLong(2, exp);
            ps.executeUpdate();
        }
    }

    private static KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private static RsaJsonWebKey buildJwk(int kid, PrivateKey privateKey) {
        RsaJsonWebKey jwk = new RsaJsonWebKey();
        jwk.setPrivateKey(privateKey);
        jwk.setKeyId("key-" + kid);
        jwk.setAlgorithm("RS256");
        jwk.setUse("sig");
        return jwk;
    }

    private static RsaJsonWebKey loadSigningKey(boolean expired) throws Exception {
        long now = Instant.now().getEpochSecond();
        String sql = expired
                ? "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY kid DESC LIMIT 1"
                : "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid DESC LIMIT 1";

        try (PreparedStatement preparedStatement = dbConnection.prepareStatement(sql)) {
            preparedStatement.setLong(1, now);

            try (ResultSet rs = preparedStatement.executeQuery()) {
                if (!rs.next()) {
                    return null;
                }

                int kid = rs.getInt("kid");
                byte[] keyBytes = rs.getBytes("key");

                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
                return buildJwk(kid, privateKey);
            }
        }
    }

    private static List<RsaJsonWebKey> loadAllValidJwks() throws Exception {
        long now = Instant.now().getEpochSecond();
        String sql = "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid ASC";

        List<RsaJsonWebKey> keys = new ArrayList<>();

        try (PreparedStatement preparedStatement = dbConnection.prepareStatement(sql)) {
            preparedStatement.setLong(1, now);

            try (ResultSet rs = preparedStatement.executeQuery()) {
                while (rs.next()) {
                    int kid = rs.getInt("kid");
                    byte[] keyBytes = rs.getBytes("key");

                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
                    keys.add(buildJwk(kid, privateKey));
                }
            }
        }

        return keys;
    }

    private static boolean hasExpiredQueryFlag(HttpExchange exchange) {
        String query = exchange.getRequestURI().getQuery();
        if (query == null || query.isBlank()) {
            return false;
        }

        for (String parameter : query.split("&")) {
            String[] parts = parameter.split("=", 2);
            String key = parts[0].trim();
            String value = parts.length > 1 ? parts[1].trim() : "";

            if ("expired".equalsIgnoreCase(key)) {
                return value.isEmpty() || "true".equalsIgnoreCase(value);
            }
        }

        return false;
    }

    private static RequestAuth parseAuthentication(HttpExchange exchange) throws IOException {
        String authHeader = exchange.getRequestHeaders().getFirst("Authorization");
        if (authHeader != null && authHeader.regionMatches(true, 0, "Basic ", 0, 6)) {
            String encoded = authHeader.substring(6).trim();
            byte[] decoded = Base64.getDecoder().decode(encoded);
            String plain = new String(decoded, StandardCharsets.UTF_8);
            String[] parts = plain.split(":", 2);

            if (parts.length == 2 && !parts[0].isBlank() && !parts[1].isBlank()) {
                return new RequestAuth(parts[0], true);
            }
        }

        byte[] bodyBytes = exchange.getRequestBody().readAllBytes();
        if (bodyBytes == null || bodyBytes.length == 0) {
            return new RequestAuth("", false);
        }

        String body = new String(bodyBytes, StandardCharsets.UTF_8);

        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> payload = OBJECT_MAPPER.readValue(body, Map.class);

            Object username = payload.get("username");
            Object password = payload.get("password");

            if (username != null && password != null
                    && !String.valueOf(username).isBlank()
                    && !String.valueOf(password).isBlank()) {
                return new RequestAuth(String.valueOf(username), true);
            }
        } catch (Exception ignored) {
            // Invalid JSON body, ignore and fail later.
        }

        return new RequestAuth("", false);
    }

    private static void writeResponse(HttpExchange exchange, int statusCode, String payload, String contentType) throws IOException {
        byte[] responseBytes = payload.getBytes(StandardCharsets.UTF_8);

        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.sendResponseHeaders(statusCode, responseBytes.length);

        try (OutputStream os = exchange.getResponseBody()) {
            os.write(responseBytes);
        }
    }

    static class JWKSHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                writeResponse(exchange, 405, "Method Not Allowed", "text/plain");
                return;
            }

            try {
                List<RsaJsonWebKey> validKeys = loadAllValidJwks();
                JsonWebKeySet keySet = new JsonWebKeySet(validKeys);
                String jwks = keySet.toJson();

                writeResponse(exchange, 200, jwks, "application/json");
            } catch (Exception e) {
                writeResponse(exchange, 500, "Failed to load JWKS", "text/plain");
            }
        }
    }

    static class AuthHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                writeResponse(exchange, 405, "Method Not Allowed", "text/plain");
                return;
            }

            RequestAuth auth;
            try {
                auth = parseAuthentication(exchange);
            } catch (Exception e) {
                writeResponse(exchange, 401, "Unauthorized", "text/plain");
                return;
            }

            if (!auth.authenticated) {
                writeResponse(exchange, 401, "Unauthorized", "text/plain");
                return;
            }

            boolean expired = hasExpiredQueryFlag(exchange);

            RsaJsonWebKey signingKey;
            try {
                signingKey = loadSigningKey(expired);
            } catch (Exception e) {
                writeResponse(exchange, 500, "Unable to load signing key", "text/plain");
                return;
            }

            if (signingKey == null) {
                writeResponse(exchange, 500, "No matching key found", "text/plain");
                return;
            }

            try {
                JwtClaims claims = new JwtClaims();
                claims.setGeneratedJwtId();
                claims.setIssuedAtToNow();
                claims.setSubject(auth.username);
                claims.setExpirationTimeMinutesInTheFuture(10);

                JsonWebSignature jws = new JsonWebSignature();
                jws.setKeyIdHeaderValue(signingKey.getKeyId());
                jws.setKey(signingKey.getPrivateKey());
                jws.setPayload(claims.toJson());
                jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

                String jwt = jws.getCompactSerialization();

                writeResponse(exchange, 200, jwt, "text/plain");
            } catch (JoseException e) {
                writeResponse(exchange, 500, "JWT signing failed", "text/plain");
            }
        }
    }

    private static class RequestAuth {
        private final String username;
        private final boolean authenticated;

        RequestAuth(String username, boolean authenticated) {
            this.username = username;
            this.authenticated = authenticated;
        }
    }
}
