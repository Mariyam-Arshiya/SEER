package com.mariyamrpt.seer_aii.detector;

import com.mariyamrpt.seer_aii.model.Detection;
import com.mariyamrpt.seer_aii.util.RegexPatterns;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class SensitiveDataDetector {

    public List<Detection> detect(String text) {
        List<Detection> detections = new ArrayList<>();

        addMatches(text, RegexPatterns.AADHAAR, "AADHAAR", "CRITICAL", detections);
        addMatches(text, RegexPatterns.PAN, "PAN", "CRITICAL", detections);
        addMatches(text, RegexPatterns.IFSC, "IFSC", "HIGH", detections);
        addMatches(text, RegexPatterns.UPI, "UPI_ID", "HIGH", detections);
        addMatches(text, RegexPatterns.EMAIL, "EMAIL", "MEDIUM", detections);
        addMatches(text, RegexPatterns.INDIAN_PHONE, "PHONE", "MEDIUM", detections);
        addMatches(text, RegexPatterns.BANK_ACCOUNT, "BANK_ACCOUNT", "HIGH", detections);

        return removeOverlaps(detections);
    }

    private void addMatches(
            String text,
            Pattern pattern,
            String type,
            String riskLevel,
            List<Detection> detections
    ) {
        Matcher matcher = pattern.matcher(text);

        while (matcher.find()) {
            detections.add(new Detection(
                    type,
                    matcher.group(),
                    riskLevel,
                    matcher.start(),
                    matcher.end()
            ));
        }
    }

    private List<Detection> removeOverlaps(List<Detection> detections) {
        detections.sort(
                Comparator.comparingInt(
                        (Detection item) -> item.getEnd() - item.getStart()
                ).reversed()
        );

        List<Detection> accepted = new ArrayList<>();

        for (Detection candidate : detections) {
            boolean overlapFound = accepted.stream().anyMatch(existing ->
                    candidate.getStart() < existing.getEnd()
                            && existing.getStart() < candidate.getEnd()
            );

            if (!overlapFound) {
                accepted.add(candidate);
            }
        }

        accepted.sort(Comparator.comparingInt(Detection::getStart));
        return accepted;
    }
}