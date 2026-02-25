namespace System.Xml
{
	/// <summary>Represents the XML type for the string. This allows the string to be read as a particular XML type, for example a CDATA section type.</summary>
	public enum XmlTokenizedType
	{
		/// <summary>CDATA type.</summary>
		CDATA = 0,
		/// <summary>ID type.</summary>
		ID = 1,
		/// <summary>IDREF type.</summary>
		IDREF = 2,
		/// <summary>IDREFS type.</summary>
		IDREFS = 3,
		/// <summary>ENTITY type.</summary>
		ENTITY = 4,
		/// <summary>ENTITIES type.</summary>
		ENTITIES = 5,
		/// <summary>NMTOKEN type.</summary>
		NMTOKEN = 6,
		/// <summary>NMTOKENS type.</summary>
		NMTOKENS = 7,
		/// <summary>NOTATION type.</summary>
		NOTATION = 8,
		/// <summary>ENUMERATION type.</summary>
		ENUMERATION = 9,
		/// <summary>QName type.</summary>
		QName = 10,
		/// <summary>NCName type.</summary>
		NCName = 11,
		/// <summary>No type.</summary>
		None = 12
	}
}
