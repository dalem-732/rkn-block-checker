package dev.rknchecker.android;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.text.InputType;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;

import java.util.List;
import java.util.Locale;
import java.util.concurrent.Future;

public final class MainActivity extends Activity {
    private final RknCheckEngine engine = new RknCheckEngine();

    private LinearLayout resultsContainer;
    private ProgressBar progressBar;
    private TextView statusText;
    private Button runButton;
    private Button urlButton;
    private EditText urlInput;
    private Future<?> currentRun;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(buildContentView());
    }

    @Override
    protected void onDestroy() {
        if (currentRun != null) {
            currentRun.cancel(true);
        }
        engine.shutdown();
        super.onDestroy();
    }

    private View buildContentView() {
        int pad = dp(16);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(pad, pad, pad, pad);
        root.setBackgroundColor(Color.rgb(248, 250, 252));

        TextView title = new TextView(this);
        title.setText("RKN Block Checker");
        title.setTextColor(Color.rgb(15, 23, 42));
        title.setTextSize(24);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(title, matchWrap());

        TextView subtitle = new TextView(this);
        subtitle.setText("Diagnose DNS, TCP, TLS and HTTP blocking signals on this Android device.");
        subtitle.setTextColor(Color.rgb(71, 85, 105));
        subtitle.setTextSize(14);
        subtitle.setPadding(0, dp(6), 0, dp(14));
        root.addView(subtitle, matchWrap());

        runButton = new Button(this);
        runButton.setText("Run built-in check");
        runButton.setAllCaps(false);
        runButton.setOnClickListener(v -> startDefaultCheck());
        root.addView(runButton, matchWrap());

        urlInput = new EditText(this);
        urlInput.setHint("example.com or https://example.com");
        urlInput.setSingleLine(true);
        urlInput.setInputType(InputType.TYPE_TEXT_VARIATION_URI);
        urlInput.setPadding(urlInput.getPaddingLeft(), dp(10), urlInput.getPaddingRight(), dp(10));
        root.addView(urlInput, matchWrap());

        urlButton = new Button(this);
        urlButton.setText("Check URL");
        urlButton.setAllCaps(false);
        urlButton.setOnClickListener(v -> startUrlCheck());
        root.addView(urlButton, matchWrap());

        progressBar = new ProgressBar(this);
        progressBar.setIndeterminate(true);
        progressBar.setVisibility(View.GONE);
        root.addView(progressBar, matchWrap());

        statusText = new TextView(this);
        statusText.setText("Ready.");
        statusText.setTextColor(Color.rgb(51, 65, 85));
        statusText.setPadding(0, dp(8), 0, dp(8));
        root.addView(statusText, matchWrap());

        ScrollView scrollView = new ScrollView(this);
        resultsContainer = new LinearLayout(this);
        resultsContainer.setOrientation(LinearLayout.VERTICAL);
        scrollView.addView(resultsContainer);
        root.addView(scrollView, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                0,
                1f
        ));

        return root;
    }

    private void startDefaultCheck() {
        setRunning(true, "Starting built-in whitelist/blacklist check...");
        resultsContainer.removeAllViews();
        addSection("Whitelist and blacklist");
        currentRun = engine.checkDefault(new UiListener());
    }

    private void startUrlCheck() {
        String rawUrl = urlInput.getText().toString().trim();
        if (rawUrl.isEmpty()) {
            statusText.setText("Enter a URL or hostname first.");
            return;
        }

        setRunning(true, "Starting ad-hoc URL check...");
        resultsContainer.removeAllViews();
        addSection("Ad-hoc URL");
        currentRun = engine.checkAdHoc(rawUrl, new UiListener());
    }

    private void setRunning(boolean running, String message) {
        runButton.setEnabled(!running);
        urlButton.setEnabled(!running);
        progressBar.setVisibility(running ? View.VISIBLE : View.GONE);
        statusText.setText(message);
    }

    private void addSection(String title) {
        TextView view = new TextView(this);
        view.setText(title);
        view.setTextColor(Color.rgb(15, 118, 110));
        view.setTextSize(18);
        view.setTypeface(Typeface.DEFAULT_BOLD);
        view.setPadding(0, dp(14), 0, dp(8));
        resultsContainer.addView(view, matchWrap());
    }

    private void addResult(String section, RknCheckEngine.CheckResult result) {
        TextView view = new TextView(this);
        view.setText(formatResult(section, result));
        view.setTextColor(colorFor(result.verdict));
        view.setTextSize(14);
        view.setPadding(dp(12), dp(10), dp(12), dp(10));
        view.setBackgroundColor(Color.WHITE);
        LinearLayout.LayoutParams params = matchWrap();
        params.setMargins(0, 0, 0, dp(8));
        resultsContainer.addView(view, params);
    }

    private void addSummary(String summary) {
        TextView view = new TextView(this);
        view.setText(summary);
        view.setTextColor(Color.rgb(15, 23, 42));
        view.setTextSize(15);
        view.setTypeface(Typeface.DEFAULT_BOLD);
        view.setPadding(dp(12), dp(12), dp(12), dp(12));
        view.setBackgroundColor(Color.rgb(226, 232, 240));
        resultsContainer.addView(view, matchWrap());
    }

    private String formatResult(String section, RknCheckEngine.CheckResult result) {
        StringBuilder out = new StringBuilder();
        out.append(section).append(" / ").append(result.name).append('\n');
        out.append(result.label()).append(" (").append(result.confidence).append(")").append('\n');
        out.append(result.url).append('\n');
        out.append("TCP: ").append(formatMs(result.tcpTimeMs))
                .append("  TLS: ").append(formatMs(result.tlsTimeMs))
                .append("  HTTP: ").append(result.statusCode == null ? "-" : result.statusCode)
                .append("  PLT: ").append(formatMs(result.pageLoadTimeMs));

        if (!result.notes.isEmpty()) {
            out.append('\n');
            for (String note : result.notes) {
                out.append("- ").append(note).append('\n');
            }
        }
        return out.toString().trim();
    }

    private static String formatMs(Double value) {
        if (value == null) {
            return "-";
        }
        return String.format(Locale.US, "%.0fms", value);
    }

    private int colorFor(RknCheckEngine.Verdict verdict) {
        switch (verdict) {
            case OK:
                return Color.rgb(22, 101, 52);
            case DNS_BLOCK:
            case TCP_RESET:
            case TLS_BLOCK:
            case HTTP_STUB:
                return Color.rgb(153, 27, 27);
            case TIMEOUT:
                return Color.rgb(146, 64, 14);
            default:
                return Color.rgb(51, 65, 85);
        }
    }

    private LinearLayout.LayoutParams matchWrap() {
        return new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
        );
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    private final class UiListener implements RknCheckEngine.Listener {
        @Override
        public void onStarted(int total) {
            runOnUiThread(() -> statusText.setText("0/" + total + " probes completed."));
        }

        @Override
        public void onResult(String section, RknCheckEngine.CheckResult result, int completed, int total) {
            runOnUiThread(() -> {
                addResult(section, result);
                statusText.setText(completed + "/" + total + " probes completed.");
            });
        }

        @Override
        public void onFinished(List<RknCheckEngine.CheckResult> whiteResults,
                               List<RknCheckEngine.CheckResult> blackResults) {
            runOnUiThread(() -> {
                addSummary(RknCheckEngine.summarize(whiteResults, blackResults));
                setRunning(false, "Finished.");
            });
        }

        @Override
        public void onError(Throwable error) {
            runOnUiThread(() -> setRunning(false, "Check failed: " + error.getMessage()));
        }
    }
}
