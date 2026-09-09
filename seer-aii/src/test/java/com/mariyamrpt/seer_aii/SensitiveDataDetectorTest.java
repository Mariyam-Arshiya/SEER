package com.mariyamrpt.seer_aii;

import com.mariyamrpt.seer_aii.detector.SensitiveDataDetector;
import com.mariyamrpt.seer_aii.model.Detection;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SensitiveDataDetectorTest {
    private final SensitiveDataDetector detector = new SensitiveDataDetector();

    @Test
    void detectsAndRedactsPanAndEmailWithoutReturningRawValues() {
        String input = "Synthetic PAN ABCDE1234F and email demo@example.com";

        List<Detection> detections = detector.detect(input, "chatgpt.com");

        assertThat(detections).extracting(Detection::type).containsExactly("PAN_LIKE", "EMAIL");
        assertThat(detector.redact(input, detections)).isEqualTo("Synthetic PAN [PAN-REDACTED] and email [EMAIL-REDACTED]");
        assertThat(detections).noneMatch(d -> d.safePreview().contains("ABCDE1234F"));
    }

    @Test
    void rejectsInvalidPaymentCardCandidate() {
        assertThat(detector.detect("Card 4111 1111 1111 1112", "chatgpt.com")).isEmpty();
    }

    @Test
    void detectsPasswordOnlyWithContext() {
        assertThat(detector.detect("password: synthetic-secret-value", "local-console"))
                .extracting(Detection::type).containsExactly("PASSWORD_IN_CONTEXT");
        assertThat(detector.detect("the word password is ordinary", "local-console")).isEmpty();
    }
}
