namespace System.Security.Cryptography.Pkcs
{
	/// <summary>The <see cref="T:System.Security.Cryptography.Pkcs.RecipientInfoType" /> enumeration defines the types of recipient information.</summary>
	public enum RecipientInfoType
	{
		/// <summary>The recipient information type is unknown.</summary>
		Unknown = 0,
		/// <summary>Key transport recipient information.</summary>
		KeyTransport = 1,
		/// <summary>Key agreement recipient information.</summary>
		KeyAgreement = 2
	}
}
