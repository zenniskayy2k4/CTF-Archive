namespace System
{
	/// <summary>Defines host name types for the <see cref="M:System.Uri.CheckHostName(System.String)" /> method.</summary>
	public enum UriHostNameType
	{
		/// <summary>The type of the host name is not supplied.</summary>
		Unknown = 0,
		/// <summary>The host is set, but the type cannot be determined.</summary>
		Basic = 1,
		/// <summary>The host name is a domain name system (DNS) style host name.</summary>
		Dns = 2,
		/// <summary>The host name is an Internet Protocol (IP) version 4 host address.</summary>
		IPv4 = 3,
		/// <summary>The host name is an Internet Protocol (IP) version 6 host address.</summary>
		IPv6 = 4
	}
}
