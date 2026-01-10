package burp.parameters;

public class Parameter {
    private final String name;
    private final String value;
    private final String type;
    private final int riskScore;

    public Parameter(String name, String value, String type, int riskScore) {
        this.name = name;
        this.value = value;
        this.type = type;
        this.riskScore = riskScore;
    }

    public String getName() {
        return name;
    }

    public String getValue() {
        return value;
    }

    public String getType() {
        return type;
    }

    public int getRiskScore() {
        return riskScore;
    }
}
