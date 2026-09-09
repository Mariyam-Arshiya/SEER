package com.mariyamrpt.seer_aii.util;
import java.util.regex.Pattern;
public final class RegexPatterns {
  private RegexPatterns() { }
  public static final Pattern AADHAAR=Pattern.compile("(?<!\\d)([2-9]\\d{3}[ -]?\\d{4}[ -]?\\d{4})(?!\\d)");
  public static final Pattern PAN=Pattern.compile("(?<![A-Z0-9])[A-Z]{5}\\d{4}[A-Z](?![A-Z0-9])");
  public static final Pattern PHONE=Pattern.compile("(?<!\\d)(?:\\+91[ -]?)?[6-9]\\d{9}(?!\\d)");
  public static final Pattern EMAIL=Pattern.compile("(?<![\\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}(?![\\w.-])");
  public static final Pattern IFSC=Pattern.compile("(?<![A-Za-z0-9])[A-Z]{4}0[A-Z0-9]{6}(?![A-Za-z0-9])");
  public static final Pattern UPI=Pattern.compile("(?<![\\w.-])[A-Za-z0-9][A-Za-z0-9._-]{1,50}@(okaxis|okhdfcbank|oksbi|okicici|ybl|ibl|axl|paytm|upi|apl|sbi|hdfcbank)(?![\\w.-])",Pattern.CASE_INSENSITIVE);
  public static final Pattern CARD=Pattern.compile("(?<!\\d)(?:\\d[ -]?){13,19}(?!\\d)");
  public static final Pattern NUMBER=Pattern.compile("(?<!\\d)\\d{9,18}(?!\\d)");
  public static final Pattern SECRET=Pattern.compile("(?i)(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|sk-proj-[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|(?:api[_-]?key|token|secret)\\s*[:=]\\s*['\"]?[^\\s'\"]{12,})");
  public static final Pattern PASSWORD=Pattern.compile("(?i)(?:password|passwd|pwd|db_password)\\s*[:=]\\s*[^\\s,;]+");
  public static final Pattern PIN=Pattern.compile("(?<!\\d)\\d{6}(?!\\d)");
}
