namespace MPPM.UI.Common;

/// <summary>
/// The actions that are available to a user through an interface
/// </summary>
public interface IUserActions
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="vaultSnowflake"></param>
    /// <returns></returns>
    bool Authenticate(int vaultSnowflake);
    
    /// <summary>
    /// Inserts a password object into the vault
    /// </summary>
    /// <param name="passwordName">Password Identifier</param>
    /// <param name="password">Password for the new item</param>
    /// <returns></returns>
    bool Insert(string passwordName, string password);
    
    /// <summary>
    /// Removes a password object from the vault
    /// </summary>
    /// <param name="passwordName">Password to remove</param>
    /// <returns></returns>
    bool Remove(string passwordName);
    
    /// <summary>
    /// Updates a password object in the vault
    /// </summary>
    /// <param name="passwordName">Password Identifier</param>
    /// <param name="updatedPassword">Password to update</param>
    /// <returns></returns>
    bool Update(string passwordName, string updatedPassword);
    
    /// <summary>
    /// Shares a password object in the vault
    /// </summary>
    /// <param name="passwordName">Password Identifier</param>
    /// <param name="vaultSnowflake">Vault Snowflake to share the password with</param>
    /// <returns></returns>
    bool Share(string passwordName, int vaultSnowflake);
    
    /// <summary>
    /// Revokes a shared password object in the vault and flags it for change
    /// </summary>
    /// <param name="passwordName">Password Identifier</param>
    /// <param name="vaultSnowflake">Revoke the shared password from this other vault</param>
    /// <returns></returns>
    bool Revoke(string passwordName, int vaultSnowflake);
    
    /// <summary>
    /// Flags a password to be changed
    /// </summary>
    /// <param name="passwordName">Password that should be updated</param>
    void FlagForChange(string passwordName);
}