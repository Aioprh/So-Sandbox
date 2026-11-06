package com.example.anative.ui;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Bundle;
import android.text.TextUtils;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.example.anative.R;
import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.button.MaterialButton;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

/**
 * 字符串解码试验台：Base64 / Hex / URL / 单字节 XOR 爆破 / RC4。
 * 用于处理 SO 里常见的轻量混淆字符串。
 */
public class StringDecoderActivity extends AppCompatActivity {

    private EditText etInput;
    private EditText etKey;
    private TextView tvOutput;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_string_decoder);

        MaterialToolbar toolbar = findViewById(R.id.toolbar);
        toolbar.setNavigationOnClickListener(v -> finish());

        etInput = findViewById(R.id.et_input);
        etKey = findViewById(R.id.et_key);
        tvOutput = findViewById(R.id.tv_output);

        MaterialButton btnAuto = findViewById(R.id.btn_auto);
        MaterialButton btnXor = findViewById(R.id.btn_xor);
        MaterialButton btnRc4 = findViewById(R.id.btn_rc4);
        MaterialButton btnCopy = findViewById(R.id.btn_copy);

        btnAuto.setOnClickListener(v -> runAuto());
        btnXor.setOnClickListener(v -> runXor());
        btnRc4.setOnClickListener(v -> runRc4());
        btnCopy.setOnClickListener(v -> copyOutput());
    }

    private String input() {
        return etInput.getText() == null ? "" : etInput.getText().toString().trim();
    }

    private void runAuto() {
        String text = input();
        if (text.isEmpty()) {
            Toast.makeText(this, "先粘贴要解码的字符串", Toast.LENGTH_SHORT).show();
            return;
        }
        List<Candidate> candidates = new ArrayList<>();
        candidates.add(new Candidate("原文", text));

        String base64 = tryBase64(text);
        if (base64 != null) {
            candidates.add(new Candidate("Base64", base64));
        }
        String hex = tryHex(text);
        if (hex != null) {
            candidates.add(new Candidate("Hex", hex));
        }
        String url = tryUrl(text);
        if (url != null) {
            candidates.add(new Candidate("URL", url));
        }
        candidates.addAll(xorCandidates(text, 3));

        candidates.sort((a, b) -> Double.compare(b.score, a.score));
        render("自动尝试（按可读性排序）", candidates);
    }

    private void runXor() {
        String text = input();
        if (text.isEmpty()) {
            Toast.makeText(this, "先粘贴要解码的字符串", Toast.LENGTH_SHORT).show();
            return;
        }
        List<Candidate> candidates = xorCandidates(text, 8);
        if (candidates.isEmpty()) {
            tvOutput.setText("没有找到可打印结果，试试 RC4 或确认输入格式。");
            return;
        }
        render("单字节 XOR 爆破（Top 8）", candidates);
    }

    private void runRc4() {
        String text = input();
        String key = etKey.getText() == null ? "" : etKey.getText().toString();
        if (text.isEmpty()) {
            Toast.makeText(this, "先粘贴要解码的字符串", Toast.LENGTH_SHORT).show();
            return;
        }
        if (key.isEmpty()) {
            Toast.makeText(this, "RC4 需要填写密钥", Toast.LENGTH_SHORT).show();
            return;
        }
        byte[] data = decodeInputBytes(text);
        if (data == null) {
            tvOutput.setText("输入需为 Hex 或 Base64 字节串。");
            return;
        }
        byte[] out = rc4(data, key.getBytes(StandardCharsets.UTF_8));
        List<Candidate> candidates = new ArrayList<>();
        candidates.add(new Candidate("RC4 (key=" + key + ")", new String(out, StandardCharsets.UTF_8)));
        render("RC4 解密", candidates);
    }

    private void render(String title, List<Candidate> candidates) {
        StringBuilder sb = new StringBuilder();
        sb.append(title).append("\n\n");
        for (int i = 0; i < candidates.size(); i++) {
            Candidate candidate = candidates.get(i);
            sb.append("── ").append(i + 1).append(". ").append(candidate.label)
                    .append("  [可读度 ").append(Math.round(candidate.score * 100)).append("%]\n");
            sb.append(candidate.text).append("\n\n");
        }
        tvOutput.setText(sb.toString());
    }

    private void copyOutput() {
        CharSequence text = tvOutput.getText();
        if (TextUtils.isEmpty(text)) {
            return;
        }
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (cm != null) {
            cm.setPrimaryClip(ClipData.newPlainText("decoded", text));
            Toast.makeText(this, "已复制结果", Toast.LENGTH_SHORT).show();
        }
    }

    // ==================== 解码实现 ====================

    private static String tryBase64(String text) {
        if (!text.matches("[A-Za-z0-9+/=\\r\\n]{8,}")) {
            return null;
        }
        try {
            byte[] data = Base64.getMimeDecoder().decode(text);
            String out = new String(data, StandardCharsets.UTF_8);
            return score(out) > 0.6 ? out : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static String tryHex(String text) {
        String compact = text.replace(" ", "").replace("0x", "").replace("0X", "")
                .replace("\\x", "").replace("\n", "");
        if (compact.length() < 4 || compact.length() % 2 != 0 || !compact.matches("[0-9a-fA-F]+")) {
            return null;
        }
        try {
            byte[] data = new byte[compact.length() / 2];
            for (int i = 0; i < data.length; i++) {
                data[i] = (byte) Integer.parseInt(compact.substring(i * 2, i * 2 + 2), 16);
            }
            String out = new String(data, StandardCharsets.UTF_8);
            return score(out) > 0.6 ? out : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static String tryUrl(String text) {
        if (!text.contains("%")) {
            return null;
        }
        try {
            String out = URLDecoder.decode(text, "UTF-8");
            return out.equals(text) ? null : out;
        } catch (Exception e) {
            return null;
        }
    }

    private static List<Candidate> xorCandidates(String text, int top) {
        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        List<Candidate> results = new ArrayList<>();
        for (int key = 1; key < 256; key++) {
            byte[] out = new byte[data.length];
            for (int i = 0; i < data.length; i++) {
                out[i] = (byte) (data[i] ^ key);
            }
            String decoded = new String(out, StandardCharsets.UTF_8);
            double score = score(decoded);
            if (score >= 0.75) {
                results.add(new Candidate(String.format(Locale.US, "XOR key=0x%02X", key), decoded, score));
            }
        }
        results.sort((a, b) -> Double.compare(b.score, a.score));
        return results.size() > top ? new ArrayList<>(results.subList(0, top)) : results;
    }

    private static double score(String text) {
        if (text == null || text.isEmpty()) {
            return 0;
        }
        int printable = 0;
        int letters = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c >= 0x20 && c != 0x7F && (c < 0x7F || c > 0x9F)) {
                printable++;
            }
            if (Character.isLetterOrDigit(c) || c == '_' || c == '.' || c == '/' || c == ':') {
                letters++;
            }
        }
        return (printable * 0.6 + letters * 0.4) / text.length();
    }

    private static byte[] decodeInputBytes(String text) {
        String trimmed = text.trim();
        if (trimmed.matches("[0-9a-fA-F\\s]+")) {
            String compact = trimmed.replace(" ", "").replace("\n", "");
            if (compact.length() % 2 == 0) {
                byte[] data = new byte[compact.length() / 2];
                for (int i = 0; i < data.length; i++) {
                    data[i] = (byte) Integer.parseInt(compact.substring(i * 2, i * 2 + 2), 16);
                }
                return data;
            }
        }
        try {
            return Base64.getMimeDecoder().decode(trimmed);
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] rc4(byte[] data, byte[] key) {
        int[] s = new int[256];
        for (int i = 0; i < 256; i++) {
            s[i] = i;
        }
        int j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + s[i] + (key[i % key.length] & 0xFF)) & 0xFF;
            int tmp = s[i];
            s[i] = s[j];
            s[j] = tmp;
        }
        byte[] out = new byte[data.length];
        int i = 0;
        j = 0;
        for (int k = 0; k < data.length; k++) {
            i = (i + 1) & 0xFF;
            j = (j + s[i]) & 0xFF;
            int tmp = s[i];
            s[i] = s[j];
            s[j] = tmp;
            int t = (s[i] + s[j]) & 0xFF;
            out[k] = (byte) (data[k] ^ s[t]);
        }
        return out;
    }

    private static class Candidate {
        final String label;
        final String text;
        final double score;

        Candidate(String label, String text) {
            this(label, text, score(text));
        }

        Candidate(String label, String text, double score) {
            this.label = label;
            this.text = text;
            this.score = score;
        }
    }
}
