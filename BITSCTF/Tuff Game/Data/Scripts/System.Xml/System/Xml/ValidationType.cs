namespace System.Xml
{
	/// <summary>Specifies the type of validation to perform.</summary>
	public enum ValidationType
	{
		/// <summary>No validation is performed. This setting creates an XML 1.0 compliant non-validating parser.</summary>
		None = 0,
		/// <summary>Validates if DTD or schema information is found.</summary>
		[Obsolete("Validation type should be specified as DTD or Schema.")]
		Auto = 1,
		/// <summary>Validates according to the DTD.</summary>
		DTD = 2,
		/// <summary>Validate according to XML-Data Reduced (XDR) schemas, including inline XDR schemas. XDR schemas are recognized using the <see langword="x-schema" /> namespace prefix or the <see cref="P:System.Xml.XmlValidatingReader.Schemas" /> property.</summary>
		[Obsolete("XDR Validation through XmlValidatingReader is obsoleted")]
		XDR = 3,
		/// <summary>Validate according to XML Schema definition language (XSD) schemas, including inline XML Schemas. XML Schemas are associated with namespace URIs either by using the <see langword="schemaLocation" /> attribute or the provided <see langword="Schemas" /> property.</summary>
		Schema = 4
	}
}
