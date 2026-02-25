namespace System.Xml.Schema
{
	/// <summary>Enumerations for the content model of the complex type. This represents the content in the post-schema-validation information set (infoset).</summary>
	public enum XmlSchemaContentType
	{
		/// <summary>Text-only content.</summary>
		TextOnly = 0,
		/// <summary>Empty content.</summary>
		Empty = 1,
		/// <summary>Element-only content.</summary>
		ElementOnly = 2,
		/// <summary>Mixed content.</summary>
		Mixed = 3
	}
}
