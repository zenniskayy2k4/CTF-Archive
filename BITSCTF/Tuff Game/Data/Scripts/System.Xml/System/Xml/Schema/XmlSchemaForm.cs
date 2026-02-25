using System.Xml.Serialization;

namespace System.Xml.Schema
{
	/// <summary>Indicates if attributes or elements need to be qualified with a namespace prefix.</summary>
	public enum XmlSchemaForm
	{
		/// <summary>Element and attribute form is not specified in the schema.</summary>
		[XmlIgnore]
		None = 0,
		/// <summary>Elements and attributes must be qualified with a namespace prefix.</summary>
		[XmlEnum("qualified")]
		Qualified = 1,
		/// <summary>Elements and attributes are not required to be qualified with a namespace prefix.</summary>
		[XmlEnum("unqualified")]
		Unqualified = 2
	}
}
