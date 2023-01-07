
namespace MPPM.UI.Terminal;

/// <summary>
/// The commands that we are allowed to execute through the terminal user interface
/// </summary>
public enum Command
{
    /// <summary>
    /// Command to add an item to the vault
    /// </summary>
    Add,
    
    /// <summary>
    /// Command to remove an item from the vault
    /// </summary>
    Remove,
    
    /// <summary>
    /// Command to update an old password with a new password in the vault
    /// </summary>
    Update,
    
    /// <summary>
    /// Command to share a password with another vault
    /// </summary>
    Share
}

public class Program
{
    /// <summary>
    /// Command entrypoint for Terminal User Interface
    /// </summary>
    /// <param name="command">The command to execute</param>
    /// <param name="name">The name of the item to add</param>
    /// <param name="password">The password to add or update</param>
    static void Main(Command command = Command.Add, string? name = null, string? password = null)
    {
        Console.WriteLine($"Command {command}, Name: {name}, Password: {password}");
    }
}

