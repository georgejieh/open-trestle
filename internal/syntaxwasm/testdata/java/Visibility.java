public interface Codec {
    String encode(String value);
    private String normalize(String value) { return value; }
}

class Hidden {
    public void run() {}
}
