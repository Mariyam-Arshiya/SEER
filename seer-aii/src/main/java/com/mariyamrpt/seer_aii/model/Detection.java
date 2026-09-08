package com.mariyamrpt.seer_aii.model;

public class Detection {

    private String type;
    private String value;
    private String riskLevel;
    private int start;
    private int end;

    public Detection() {
    }

    public Detection(String type, String value, String riskLevel, int start, int end) {
        this.type = type;
        this.value = value;
        this.riskLevel = riskLevel;
        this.start = start;
        this.end = end;
    }

    public String getType() {
        return type;
    }

    public String getValue() {
        return value;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public int getStart() {
        return start;
    }

    public int getEnd() {
        return end;
    }
}