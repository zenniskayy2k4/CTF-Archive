using System.Xml.Serialization;

namespace System.Xml.Schema
{
	/// <summary>Indicator of how the attribute is used.</summary>
	public enum XmlSchemaUse
	{
		/// <summary>Attribute use not specified.</summary>
		[XmlIgnore]
		None = 0,
		/// <summary>Attribute is optional.</summary>
		[XmlEnum("optional")]
		Optional = 1,
		/// <summary>Attribute cannot be used.</summary>
		[XmlEnum("prohibited")]
		Prohibited = 2,
		/// <summary>Attribute must appear once.</summary>
		[XmlEnum("required")]
		Required = 3
	}
}
