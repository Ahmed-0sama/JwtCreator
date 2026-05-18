namespace JwtStudio.Services;

public class TamperState
{
    public string? Token { get; set; }
    public string? Secret { get; set; }

    public (string? token, string? secret) Consume()
    {
        var t = Token; var s = Secret;
        Token = null; Secret = null;
        return (t, s);
    }
}