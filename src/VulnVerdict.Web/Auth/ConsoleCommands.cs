using VulnVerdict.Core.Services;

namespace VulnVerdict.Web;

/// <summary>
/// Commands run on the console host instead of starting the web server, for when nobody can sign in:
/// <c>dotnet VulnVerdict.Web.dll reset-2fa &lt;username&gt;</c>. Whoever can run this already has the data folder
/// and the database, so it asks for nothing more; it is written to the audit log as "console".
/// </summary>
public static class ConsoleCommands
{
    public const string ResetTwoFactor = "reset-2fa";

    /// <summary>True when the arguments were a command and it has run; the caller then exits without serving.</summary>
    public static async Task<bool> RunAsync(string[] args, IServiceProvider services)
    {
        if (args.Length == 0 || !args[0].Equals(ResetTwoFactor, StringComparison.OrdinalIgnoreCase)) return false;
        if (args.Length != 2 || string.IsNullOrWhiteSpace(args[1]))
        {
            Console.Error.WriteLine("Usage: dotnet VulnVerdict.Web.dll " + ResetTwoFactor + " <username>");
            Environment.ExitCode = 2;
            return true;
        }
        var done = await services.GetRequiredService<TwoFactorService>().ResetByUsernameAsync(args[1], "console");
        if (done)
            Console.WriteLine("Two-factor removed and lockouts cleared for " + args[1].Trim() + ". Their open sessions have ended; they sign in with the password"
                + " and, if two-factor is required, enrol again straight away.");
        else
        {
            Console.Error.WriteLine("No local account named " + args[1].Trim() + ". Nothing was changed.");
            Environment.ExitCode = 1;
        }
        return true;
    }
}
