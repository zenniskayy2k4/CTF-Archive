namespace System.Xml
{
	/// <summary>Specifies how white space is handled.</summary>
	public enum WhitespaceHandling
	{
		/// <summary>Return <see langword="Whitespace" /> and <see langword="SignificantWhitespace" /> nodes. This is the default.</summary>
		All = 0,
		/// <summary>Return <see langword="SignificantWhitespace" /> nodes only.</summary>
		Significant = 1,
		/// <summary>Return no <see langword="Whitespace" /> and no <see langword="SignificantWhitespace" /> nodes.</summary>
		None = 2
	}
}
