public interface ICodec
{
    string Encode(string value);
    private string Normalize(string value) => value;
    protected static void Log() {}
}
