namespace System.Data.SqlClient
{
	/// <summary>Describes the different SQL authentication methods that can be used by a client connecting to Azure SQL Database. For details, see Connecting to SQL Database By Using Azure Active Directory Authentication.</summary>
	public enum SqlAuthenticationMethod
	{
		/// <summary>The authentication method is not specified.</summary>
		NotSpecified = 0,
		/// <summary>The authentication method is Sql Password.</summary>
		SqlPassword = 1,
		/// <summary>The authentication method uses Active Directory Password. Use Active Directory Password to connect to a SQL Database using an Azure AD principal name and password.</summary>
		ActiveDirectoryPassword = 2,
		/// <summary>The authentication method uses Active Directory Integrated. Use Active Directory Integrated to connect to a SQL Database using integrated Windows authentication.</summary>
		ActiveDirectoryIntegrated = 3,
		/// <summary>The authentication method uses Active Directory Interactive. Available since the .NET Framework 4.7.2.</summary>
		ActiveDirectoryInteractive = 4
	}
}
