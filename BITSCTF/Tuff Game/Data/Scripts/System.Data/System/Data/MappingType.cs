namespace System.Data
{
	/// <summary>Specifies how a <see cref="T:System.Data.DataColumn" /> is mapped.</summary>
	public enum MappingType
	{
		/// <summary>The column is mapped to an XML element.</summary>
		Element = 1,
		/// <summary>The column is mapped to an XML attribute.</summary>
		Attribute = 2,
		/// <summary>The column is mapped to an <see cref="T:System.Xml.XmlText" /> node.</summary>
		SimpleContent = 3,
		/// <summary>The column is mapped to an internal structure.</summary>
		Hidden = 4
	}
}
