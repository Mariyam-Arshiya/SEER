package com.mariyamrpt.seer_aii.model;
public record Detection(String type, String severity, String confidence, int start, int end, String safePreview, String[] reasons, String recommendedAction) { }
