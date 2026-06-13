package dev.rknchecker.android;

import android.os.Build;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public final class RknCheckEngine {
    private static final int DEFAULT_PORT = 443;
    private static final int DEFAULT_TIMEOUT_MS = 5_000;
    private static final int WORKERS = 6;
    private static final int BODY_SNIPPET_LEN = 2_000;
    private static final String DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query";

    private static final Map<String, String> WHITE_URLS = urls(new String[][] {
            {"gosuslugi", "https://www.gosuslugi.ru/"},
            {"gov.ru", "https://www.gov.ru/"},
            {"mos.ru", "https://www.mos.ru/"},
            {"rkn", "https://rkn.gov.ru/"},
            {"nalog", "https://www.nalog.gov.ru/"},
            {"yandex", "https://ya.ru/"},
            {"yandex-maps", "https://yandex.ru/maps/"},
            {"kinopoisk", "https://www.kinopoisk.ru/"},
            {"sberbank", "https://www.sberbank.ru/"},
            {"vtb", "https://www.vtb.ru/"},
            {"alfabank", "https://alfabank.ru/"},
            {"vk", "https://vk.com/"},
            {"ok", "https://ok.ru/"},
            {"ozon", "https://www.ozon.ru/"},
            {"wildberries", "https://www.wildberries.ru/"},
            {"avito", "https://www.avito.ru/"},
            {"lenta", "https://lenta.ru/"},
            {"rbc", "https://www.rbc.ru/"},
            {"tass", "https://tass.ru/"},
            {"rutube", "https://rutube.ru/"},
            {"dzen", "https://dzen.ru/"}
    });

    private static final Map<String, String> BLACK_URLS = urls(new String[][] {
            {"instagram", "https://www.instagram.com/"},
            {"facebook", "https://www.facebook.com/"},
            {"twitter/x", "https://x.com/"},
            {"linkedin", "https://www.linkedin.com/"},
            {"discord", "https://discord.com/"},
            {"dailymotion", "https://www.dailymotion.com/"},
            {"soap2day", "https://soap2day.day/"},
            {"rutracker", "https://rutracker.org/"},
            {"tor-project", "https://www.torproject.org/"},
            {"protonvpn", "https://protonvpn.com/"},
            {"deepl", "https://www.deepl.com/"},
            {"patreon", "https://www.patreon.com/"},
            {"bbc-russian", "https://www.bbc.com/russian"},
            {"meduza", "https://meduza.io/"},
            {"dw-russian", "https://www.dw.com/ru/"}
    });

    private static final List<String> STUB_MARKERS = Collections.unmodifiableList(Arrays.asList(
            "\u0434\u043e\u0441\u0442\u0443\u043f \u043e\u0433\u0440\u0430\u043d\u0438\u0447\u0435\u043d",
            "\u0434\u043e\u0441\u0442\u0443\u043f \u043a \u0437\u0430\u043f\u0440\u0430\u0448\u0438\u0432\u0430\u0435\u043c\u043e\u043c\u0443 \u0440\u0435\u0441\u0443\u0440\u0441\u0443",
            "\u0440\u0435\u0448\u0435\u043d\u0438\u044e \u0440\u043e\u0441\u043a\u043e\u043c\u043d\u0430\u0434\u0437\u043e\u0440\u0430",
            "\u0440\u0435\u0448\u0435\u043d\u0438\u0435\u043c \u0441\u0443\u0434\u0430",
            "\u0437\u0430\u0431\u043b\u043e\u043a\u0438\u0440\u043e\u0432\u0430\u043d",
            "blocked by roskomnadzor",
            "blocked by rkn",
            "rkn.gov.ru/org/register",
            "\u0435\u0434\u0438\u043d\u044b\u0439 \u0440\u0435\u0435\u0441\u0442\u0440",
            "\u0437\u0430\u043f\u0440\u0435\u0449\u0435\u043d"
    ));

    private static final Set<Verdict> BLOCKED_VERDICTS = Collections.unmodifiableSet(new LinkedHashSet<>(
            Arrays.asList(Verdict.DNS_BLOCK, Verdict.TCP_RESET, Verdict.TLS_BLOCK,
                    Verdict.HTTP_STUB, Verdict.TIMEOUT)
    ));

    private final ExecutorService controlExecutor = Executors.newSingleThreadExecutor();
    private final ExecutorService workerExecutor = Executors.newFixedThreadPool(WORKERS);

    public Future<?> checkDefault(Listener listener) {
        return controlExecutor.submit(() -> {
            List<CheckTask> tasks = new ArrayList<>();
            for (Map.Entry<String, String> entry : WHITE_URLS.entrySet()) {
                tasks.add(new CheckTask("Whitelist", entry.getKey(), entry.getValue()));
            }
            for (Map.Entry<String, String> entry : BLACK_URLS.entrySet()) {
                tasks.add(new CheckTask("Blacklist", entry.getKey(), entry.getValue()));
            }
            runTasks(tasks, listener);
        });
    }

    public Future<?> checkAdHoc(String rawUrl, Listener listener) {
        return controlExecutor.submit(() -> {
            String url = normalizeUrl(rawUrl);
            String name = nameForUrl(url);
            runTasks(Collections.singletonList(new CheckTask("Ad-hoc", name, url)), listener);
        });
    }

    public void shutdown() {
        controlExecutor.shutdownNow();
        workerExecutor.shutdownNow();
    }

    private void runTasks(List<CheckTask> tasks, Listener listener) {
        List<CheckResult> whiteResults = new ArrayList<>();
        List<CheckResult> blackResults = new ArrayList<>();
        int total = tasks.size();
        int completed = 0;

        try {
            listener.onStarted(total);
            ExecutorCompletionService<SectionResult> completionService =
                    new ExecutorCompletionService<>(workerExecutor);
            for (CheckTask task : tasks) {
                completionService.submit(task);
            }

            for (int i = 0; i < total; i++) {
                SectionResult sectionResult = completionService.take().get();
                completed++;

                if ("Whitelist".equals(sectionResult.section)) {
                    whiteResults.add(sectionResult.result);
                } else {
                    blackResults.add(sectionResult.result);
                }

                listener.onResult(sectionResult.section, sectionResult.result, completed, total);
            }

            listener.onFinished(whiteResults, blackResults);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            listener.onError(e);
        } catch (ExecutionException e) {
            listener.onError(e.getCause() == null ? e : e.getCause());
        } catch (RuntimeException e) {
            listener.onError(e);
        }
    }

    private static CheckResult checkUrl(String name, String rawUrl) {
        String url = normalizeUrl(rawUrl);
        String host = hostForUrl(url);
        CheckResult result = new CheckResult(name, url);

        try {
            Set<String> systemIps = resolveSystemAll(host);
            Set<String> dohIps = resolveDohAll(host);
            result.systemIps.addAll(systemIps);
            result.dohIps.addAll(dohIps);
            Collections.sort(result.systemIps);
            Collections.sort(result.dohIps);

            if (!systemIps.isEmpty()) {
                result.systemIp = result.systemIps.get(0);
            }
            if (!dohIps.isEmpty()) {
                result.dohIp = result.dohIps.get(0);
            }

            if (systemIps.isEmpty() && !dohIps.isEmpty()) {
                result.verdict = Verdict.DNS_BLOCK;
                result.confidence = Confidence.HIGH;
                result.dnsError = "system resolver failed, DoH succeeded";
                result.notes.add("system DNS does not resolve, DoH does - consistent with DNS poisoning");
                return result;
            }

            if (systemIps.isEmpty()) {
                result.verdict = Verdict.DOWN;
                result.confidence = Confidence.LOW;
                result.dnsError = "domain not resolved anywhere";
                result.notes.add("domain does not resolve via system DNS or DoH");
                return result;
            }

            if (!dohIps.isEmpty() && Collections.disjoint(systemIps, dohIps)) {
                result.dnsMismatch = true;
                result.notes.add("DNS mismatch between system resolver and DoH address sets");
            }

            if (dohIps.isEmpty()) {
                result.notes.add("DoH lookup failed - DNS poisoning comparison unavailable");
            }

            ProbeTiming tcp = checkTcp(host);
            result.tcpOk = tcp.ok;
            result.tcpTimeMs = tcp.elapsedMs;
            result.tcpError = tcp.error;
            if (!tcp.ok) {
                classifyTcpFailure(result);
                return result;
            }

            TlsProbe tls = checkTls(host);
            result.tlsOk = tls.ok;
            result.tlsTimeMs = tls.elapsedMs;
            result.tlsCertCommonName = tls.certCommonName;
            result.tlsError = tls.error;
            if (!tls.ok) {
                classifyTlsFailure(result);
                return result;
            }

            HttpProbe http = fetch(url);
            result.statusCode = http.statusCode;
            result.pageLoadTimeMs = http.elapsedMs;
            result.httpError = http.error;

            if (http.timedOut) {
                result.verdict = Verdict.TIMEOUT;
                result.confidence = Confidence.LOW;
                return result;
            }
            if (http.error != null) {
                result.verdict = Verdict.DOWN;
                result.confidence = Confidence.LOW;
                return result;
            }
            if (Integer.valueOf(451).equals(http.statusCode)) {
                result.verdict = Verdict.HTTP_STUB;
                result.confidence = Confidence.HIGH;
                result.notes.add("HTTP 451 - Unavailable For Legal Reasons");
                return result;
            }
            if (looksLikeStub(http.bodySnippet)) {
                result.verdict = Verdict.HTTP_STUB;
                result.confidence = Confidence.HIGH;
                result.notes.add("response body matches a known ISP stub-page marker");
                return result;
            }

            result.verdict = Verdict.OK;
            result.confidence = result.dnsMismatch ? Confidence.MEDIUM : Confidence.HIGH;
            return result;
        } catch (Exception e) {
            result.verdict = Verdict.UNKNOWN;
            result.confidence = Confidence.LOW;
            result.notes.add("unexpected error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            return result;
        }
    }

    private static void classifyTcpFailure(CheckResult result) {
        String error = lower(result.tcpError);
        if (error.contains("timeout")) {
            result.verdict = Verdict.TIMEOUT;
            result.confidence = Confidence.LOW;
            result.notes.add("TCP timeout on port 443");
        } else if (error.contains("reset")) {
            result.verdict = Verdict.TCP_RESET;
            result.confidence = Confidence.MEDIUM;
            result.notes.add("TCP RST received - pattern can match reset injection by a middlebox");
        } else {
            result.verdict = Verdict.DOWN;
            result.confidence = Confidence.LOW;
            result.notes.add("TCP failed: " + result.tcpError);
        }
    }

    private static void classifyTlsFailure(CheckResult result) {
        String error = lower(result.tlsError);
        result.verdict = Verdict.TLS_BLOCK;
        if (error.contains("reset")) {
            result.confidence = Confidence.MEDIUM;
            result.notes.add("TLS reset after ClientHello - consistent with SNI-based DPI filtering");
        } else if (error.contains("timeout")) {
            result.confidence = Confidence.MEDIUM;
            result.notes.add("TLS handshake timed out - consistent with DPI filtering by ClientHello");
        } else {
            result.confidence = Confidence.LOW;
            result.notes.add("TLS error: " + result.tlsError);
        }
    }

    private static ProbeTiming checkTcp(String host) {
        long start = System.nanoTime();
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, DEFAULT_PORT), DEFAULT_TIMEOUT_MS);
            return ProbeTiming.ok(elapsedMs(start));
        } catch (SocketTimeoutException e) {
            return ProbeTiming.error("timeout");
        } catch (IOException e) {
            return ProbeTiming.error(e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private static TlsProbe checkTls(String host) {
        long start = System.nanoTime();
        SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        try (SSLSocket socket = (SSLSocket) factory.createSocket()) {
            socket.connect(new InetSocketAddress(host, DEFAULT_PORT), DEFAULT_TIMEOUT_MS);
            socket.setSoTimeout(DEFAULT_TIMEOUT_MS);

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                SSLParameters parameters = socket.getSSLParameters();
                parameters.setServerNames(Collections.singletonList(new SNIHostName(host)));
                socket.setSSLParameters(parameters);
            }

            socket.startHandshake();
            return TlsProbe.ok(elapsedMs(start), extractCommonName(socket.getSession().getPeerCertificates()));
        } catch (SocketTimeoutException e) {
            return TlsProbe.error("timeout");
        } catch (IOException e) {
            return TlsProbe.error(e.getClass().getSimpleName() + ": " + e.getMessage());
        } catch (RuntimeException e) {
            return TlsProbe.error(e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private static HttpProbe fetch(String url) {
        long start = System.nanoTime();
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) new URL(url).openConnection();
            connection.setConnectTimeout(DEFAULT_TIMEOUT_MS);
            connection.setReadTimeout(DEFAULT_TIMEOUT_MS);
            connection.setInstanceFollowRedirects(true);
            for (Map.Entry<String, String> header : genericHeaders().entrySet()) {
                connection.setRequestProperty(header.getKey(), header.getValue());
            }

            int statusCode = connection.getResponseCode();
            String snippet = readSnippet(responseStream(connection), BODY_SNIPPET_LEN).toLowerCase(Locale.ROOT);
            return HttpProbe.ok(statusCode, elapsedMs(start), snippet);
        } catch (SocketTimeoutException e) {
            return HttpProbe.timeout();
        } catch (IOException e) {
            return HttpProbe.error(e.getClass().getSimpleName() + ": " + e.getMessage());
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private static Set<String> resolveSystemAll(String host) {
        Set<String> ips = new LinkedHashSet<>();
        try {
            for (InetAddress address : InetAddress.getAllByName(host)) {
                if (address instanceof Inet4Address) {
                    ips.add(address.getHostAddress());
                }
            }
        } catch (IOException ignored) {
            return Collections.emptySet();
        }
        return ips;
    }

    private static Set<String> resolveDohAll(String host) {
        HttpURLConnection connection = null;
        try {
            String encodedHost = URLEncoder.encode(host, "UTF-8");
            URL url = new URL(DOH_ENDPOINT + "?name=" + encodedHost + "&type=A");
            connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(DEFAULT_TIMEOUT_MS);
            connection.setReadTimeout(DEFAULT_TIMEOUT_MS);
            connection.setRequestProperty("accept", "application/dns-json");

            if (connection.getResponseCode() < 200 || connection.getResponseCode() >= 300) {
                return Collections.emptySet();
            }

            JSONObject json = new JSONObject(readSnippet(connection.getInputStream(), 64_000));
            JSONArray answers = json.optJSONArray("Answer");
            Set<String> ips = new LinkedHashSet<>();
            if (answers != null) {
                for (int i = 0; i < answers.length(); i++) {
                    JSONObject answer = answers.optJSONObject(i);
                    if (answer != null && answer.optInt("type") == 1) {
                        String data = answer.optString("data", "");
                        if (!data.isEmpty()) {
                            ips.add(data);
                        }
                    }
                }
            }
            return ips;
        } catch (Exception ignored) {
            return Collections.emptySet();
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    public static String summarize(List<CheckResult> whiteResults, List<CheckResult> blackResults) {
        if (whiteResults.isEmpty()) {
            return "Ad-hoc check finished. Built-in whitelist/blacklist controls are required for a network-level verdict.";
        }

        int whiteOk = countVerdict(whiteResults, Verdict.OK);
        int blackOk = countVerdict(blackResults, Verdict.OK);
        int blackBlocked = 0;
        int blackTimeout = 0;
        int blackHighConfidence = 0;
        for (CheckResult result : blackResults) {
            if (BLOCKED_VERDICTS.contains(result.verdict) && result.verdict != Verdict.TIMEOUT) {
                blackBlocked++;
            }
            if (result.verdict == Verdict.TIMEOUT) {
                blackTimeout++;
            }
            if (BLOCKED_VERDICTS.contains(result.verdict) && result.confidence == Confidence.HIGH) {
                blackHighConfidence++;
            }
        }

        StringBuilder out = new StringBuilder();
        out.append("Whitelist: ").append(whiteOk).append('/').append(whiteResults.size()).append(" working\n");
        out.append("Blacklist: ").append(blackOk).append('/').append(blackResults.size()).append(" open, ")
                .append(blackBlocked).append('/').append(blackResults.size()).append(" blocked");
        if (blackTimeout > 0) {
            out.append(", ").append(blackTimeout).append(" timed out");
        }
        out.append("\n\n").append(summaryVerdict(whiteOk, whiteResults.size(), blackOk,
                blackBlocked, blackResults.size(), blackHighConfidence, blackTimeout));
        return out.toString();
    }

    private static String summaryVerdict(int whiteOk,
                                         int whiteTotal,
                                         int blackOk,
                                         int blackBlocked,
                                         int blackTotal,
                                         int blackHighConfidence,
                                         int blackTimeout) {
        int effectiveTotal = blackTotal - blackTimeout;
        if (whiteTotal > 0 && whiteOk < whiteTotal / 2.0) {
            return "Inconclusive - control whitelist is also failing.\n"
                    + "Cannot separate censorship from a broken uplink without a working baseline.";
        }
        if (effectiveTotal <= 0) {
            return "Inconclusive - all blacklist probes timed out.";
        }
        if (blackBlocked == 0 && blackOk == effectiveTotal) {
            return "Likely NOT in an RKN-blocked zone, or VPN/proxy is masking it.";
        }
        if (blackBlocked >= effectiveTotal * 0.7) {
            if (blackHighConfidence >= effectiveTotal * 0.5) {
                return "Likely in an RKN-blocked zone (high confidence).";
            }
            return "Likely in an RKN-blocked zone (medium confidence).";
        }
        return "Partial blocks - some blacklisted sites still load.";
    }

    private static int countVerdict(List<CheckResult> results, Verdict verdict) {
        int count = 0;
        for (CheckResult result : results) {
            if (result.verdict == verdict) {
                count++;
            }
        }
        return count;
    }

    private static String normalizeUrl(String rawUrl) {
        String url = rawUrl.trim();
        if (!url.contains("://")) {
            return "https://" + url;
        }
        return url;
    }

    private static String hostForUrl(String url) {
        String host = URI.create(url).getHost();
        if (host == null || host.isEmpty()) {
            throw new IllegalArgumentException("URL has no host: " + url);
        }
        return host;
    }

    private static String nameForUrl(String url) {
        return hostForUrl(url).replace('.', '-');
    }

    private static String readSnippet(InputStream inputStream, int maxChars) throws IOException {
        if (inputStream == null) {
            return "";
        }
        StringBuilder out = new StringBuilder();
        char[] buffer = new char[1024];
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
            int read;
            while (out.length() < maxChars && (read = reader.read(buffer, 0,
                    Math.min(buffer.length, maxChars - out.length()))) != -1) {
                out.append(buffer, 0, read);
            }
        }
        return out.toString();
    }

    private static InputStream responseStream(HttpURLConnection connection) throws IOException {
        if (connection.getResponseCode() >= 400 && connection.getErrorStream() != null) {
            return connection.getErrorStream();
        }
        return connection.getInputStream();
    }

    private static boolean looksLikeStub(String bodySnippet) {
        for (String marker : STUB_MARKERS) {
            if (bodySnippet.contains(marker)) {
                return true;
            }
        }
        return false;
    }

    private static Map<String, String> genericHeaders() {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("User-Agent", "Mozilla/5.0 (Linux; Android 16) AppleWebKit/537.36 "
                + "(KHTML, like Gecko) Chrome/147.0.0.0 Mobile Safari/537.36");
        headers.put("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,"
                + "image/avif,image/webp,image/apng,*/*;q=0.8");
        headers.put("Accept-Language", "en-US,en;q=0.9");
        headers.put("Sec-Fetch-Dest", "document");
        headers.put("Sec-Fetch-Mode", "navigate");
        headers.put("Sec-Fetch-Site", "none");
        headers.put("Sec-Fetch-User", "?1");
        headers.put("Upgrade-Insecure-Requests", "1");
        return headers;
    }

    private static String extractCommonName(Certificate[] certificates) {
        if (certificates == null || certificates.length == 0
                || !(certificates[0] instanceof X509Certificate)) {
            return null;
        }
        String subject = ((X509Certificate) certificates[0]).getSubjectX500Principal().getName();
        for (String part : subject.split(",")) {
            String trimmed = part.trim();
            if (trimmed.startsWith("CN=")) {
                return trimmed.substring(3);
            }
        }
        return null;
    }

    private static double elapsedMs(long startNanos) {
        return (System.nanoTime() - startNanos) / 1_000_000.0;
    }

    private static String lower(String value) {
        return value == null ? "" : value.toLowerCase(Locale.ROOT);
    }

    private static Map<String, String> urls(String[][] pairs) {
        Map<String, String> out = new LinkedHashMap<>();
        for (String[] pair : pairs) {
            out.put(pair[0], pair[1]);
        }
        return Collections.unmodifiableMap(out);
    }

    public interface Listener {
        void onStarted(int total);
        void onResult(String section, CheckResult result, int completed, int total);
        void onFinished(List<CheckResult> whiteResults, List<CheckResult> blackResults);
        void onError(Throwable error);
    }

    public enum Verdict {
        OK,
        DNS_BLOCK,
        TCP_RESET,
        TLS_BLOCK,
        HTTP_STUB,
        TIMEOUT,
        DOWN,
        UNKNOWN
    }

    public enum Confidence {
        HIGH,
        MEDIUM,
        LOW
    }

    public static final class CheckResult {
        public final String name;
        public final String url;
        public final List<String> notes = new ArrayList<>();
        public final List<String> systemIps = new ArrayList<>();
        public final List<String> dohIps = new ArrayList<>();

        public Verdict verdict = Verdict.UNKNOWN;
        public Confidence confidence = Confidence.LOW;
        public String systemIp;
        public String dohIp;
        public boolean dnsMismatch;
        public String dnsError;
        public boolean tcpOk;
        public Double tcpTimeMs;
        public String tcpError;
        public boolean tlsOk;
        public Double tlsTimeMs;
        public String tlsCertCommonName;
        public String tlsError;
        public Integer statusCode;
        public Double pageLoadTimeMs;
        public String httpError;

        CheckResult(String name, String url) {
            this.name = name;
            this.url = url;
        }

        String label() {
            if (verdict == Verdict.OK) {
                return "OK";
            }
            if (verdict == Verdict.DOWN) {
                return "DOWN";
            }
            if (verdict == Verdict.UNKNOWN) {
                return "UNKNOWN";
            }

            String base;
            switch (verdict) {
                case DNS_BLOCK:
                    base = "DNS";
                    break;
                case TCP_RESET:
                    base = "TCP RESET";
                    break;
                case TLS_BLOCK:
                    base = "TLS DPI";
                    break;
                case HTTP_STUB:
                    base = "HTTP STUB";
                    break;
                case TIMEOUT:
                    base = "TIMEOUT";
                    break;
                default:
                    base = verdict.name();
            }

            if (confidence == Confidence.HIGH) {
                return base;
            }
            if (confidence == Confidence.MEDIUM) {
                return "LIKELY " + base;
            }
            return base + "?";
        }
    }

    private static final class CheckTask implements Callable<SectionResult> {
        private final String section;
        private final String name;
        private final String url;

        private CheckTask(String section, String name, String url) {
            this.section = section;
            this.name = name;
            this.url = url;
        }

        @Override
        public SectionResult call() {
            return new SectionResult(section, checkUrl(name, url));
        }
    }

    private static final class SectionResult {
        private final String section;
        private final CheckResult result;

        private SectionResult(String section, CheckResult result) {
            this.section = section;
            this.result = result;
        }
    }

    private static final class ProbeTiming {
        private final boolean ok;
        private final Double elapsedMs;
        private final String error;

        private ProbeTiming(boolean ok, Double elapsedMs, String error) {
            this.ok = ok;
            this.elapsedMs = elapsedMs;
            this.error = error;
        }

        private static ProbeTiming ok(double elapsedMs) {
            return new ProbeTiming(true, elapsedMs, null);
        }

        private static ProbeTiming error(String error) {
            return new ProbeTiming(false, null, error);
        }
    }

    private static final class TlsProbe {
        private final boolean ok;
        private final Double elapsedMs;
        private final String certCommonName;
        private final String error;

        private TlsProbe(boolean ok, Double elapsedMs, String certCommonName, String error) {
            this.ok = ok;
            this.elapsedMs = elapsedMs;
            this.certCommonName = certCommonName;
            this.error = error;
        }

        private static TlsProbe ok(double elapsedMs, String certCommonName) {
            return new TlsProbe(true, elapsedMs, certCommonName, null);
        }

        private static TlsProbe error(String error) {
            return new TlsProbe(false, null, null, error);
        }
    }

    private static final class HttpProbe {
        private final Integer statusCode;
        private final Double elapsedMs;
        private final String bodySnippet;
        private final String error;
        private final boolean timedOut;

        private HttpProbe(Integer statusCode,
                          Double elapsedMs,
                          String bodySnippet,
                          String error,
                          boolean timedOut) {
            this.statusCode = statusCode;
            this.elapsedMs = elapsedMs;
            this.bodySnippet = bodySnippet;
            this.error = error;
            this.timedOut = timedOut;
        }

        private static HttpProbe ok(int statusCode, double elapsedMs, String bodySnippet) {
            return new HttpProbe(statusCode, elapsedMs, bodySnippet, null, false);
        }

        private static HttpProbe timeout() {
            return new HttpProbe(null, null, "", "timeout", true);
        }

        private static HttpProbe error(String error) {
            return new HttpProbe(null, null, "", error, false);
        }
    }
}
