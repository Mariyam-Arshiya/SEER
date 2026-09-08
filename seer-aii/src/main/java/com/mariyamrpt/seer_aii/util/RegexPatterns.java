package com.mariyamrpt.seer_aii.util;

import java.util.regex.Pattern;

public final class RegexPatterns {

    private RegexPatterns() {
    }

    public static final Pattern AADHAAR = Pattern.compile(
            "\\b\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}\\b"
    );

    public static final Pattern PAN = Pattern.compile(
            "\\b[A-Z]{5}\\d{4}[A-Z]\\b"
    );

    public static final Pattern INDIAN_PHONE = Pattern.compile(
            "(?<!\\d)(?:\\+91[\\s-]?)?[6-9]\\d{9}(?!\\d)"
    );

    public static final Pattern EMAIL = Pattern.compile(
            "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b"
    );

    public static final Pattern IFSC = Pattern.compile(
            "\\b[A-Z]{4}0[A-Z0-9]{6}\\b"
    );

    public static final Pattern UPI = Pattern.compile(
            "\\b[A-Za-z0-9._-]+@(?!gmail\\b|yahoo\\b|outlook\\b)[A-Za-z]{2,}\\b",
            Pattern.CASE_INSENSITIVE
    );

    public static final Pattern BANK_ACCOUNT = Pattern.compile(
            "(?<!\\d)\\d{9,18}(?!\\d)"
    );

    public static final Pattern CREDIT_CARD = Pattern.compile(
            "\\b(?:\\d{4}[-\\s]?){3}\\d{4}\\b"
    );
}