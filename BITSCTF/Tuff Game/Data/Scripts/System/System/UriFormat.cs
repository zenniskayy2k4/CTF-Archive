namespace System
{
	/// <summary>Controls how URI information is escaped.</summary>
	public enum UriFormat
	{
		/// <summary>Escaping is performed according to the rules in RFC 2396.</summary>
		UriEscaped = 1,
		/// <summary>No escaping is performed.</summary>
		Unescaped = 2,
		/// <summary>Characters that have a reserved meaning in the requested URI components remain escaped. All others are not escaped.</summary>
		SafeUnescaped = 3
	}
}
