namespace System.Security.Cryptography.X509Certificates
{
	/// <summary>Specifies how much of the X.509 certificate chain should be included in the X.509 data.</summary>
	public enum X509IncludeOption
	{
		/// <summary>No X.509 chain information is included.</summary>
		None = 0,
		/// <summary>The entire X.509 chain is included except for the root certificate.</summary>
		ExcludeRoot = 1,
		/// <summary>Only the end certificate is included in the X.509 chain information.</summary>
		EndCertOnly = 2,
		/// <summary>The entire X.509 chain is included.</summary>
		WholeChain = 3
	}
}
