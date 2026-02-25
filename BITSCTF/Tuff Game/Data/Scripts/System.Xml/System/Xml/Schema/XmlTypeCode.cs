namespace System.Xml.Schema
{
	/// <summary>Represents the W3C XML Schema Definition Language (XSD) schema types.</summary>
	public enum XmlTypeCode
	{
		/// <summary>No type information.</summary>
		None = 0,
		/// <summary>An item such as a node or atomic value.</summary>
		Item = 1,
		/// <summary>This value supports the .NET Framework infrastructure and is not intended to be used directly from your code.</summary>
		Node = 2,
		/// <summary>This value supports the .NET Framework infrastructure and is not intended to be used directly from your code.</summary>
		Document = 3,
		/// <summary>This value supports the .NET Framework infrastructure and is not intended to be used directly from your code.</summary>
		Element = 4,
		/// <summary>This value supports the .NET Framework infrastructure and is not intended to be used directly from your code.</summary>
		Attribute = 5,
		/// <summary>This value supports the .NET Framework infrastructure and is not intended to be used directly from your code.</summary>
		Namespace = 6,
		/// <summary>This value supports the .NET Framework infrastructure and is not intended to be used directly from your code.</summary>
		ProcessingInstruction = 7,
		/// <summary>This value supports the .NET Framework infrastructure and is not intended to be used directly from your code.</summary>
		Comment = 8,
		/// <summary>This value supports the .NET Framework infrastructure and is not intended to be used directly from your code.</summary>
		Text = 9,
		/// <summary>Any atomic value of a union.</summary>
		AnyAtomicType = 10,
		/// <summary>An untyped atomic value.</summary>
		UntypedAtomic = 11,
		/// <summary>A W3C XML Schema <see langword="xs:string" /> type.</summary>
		String = 12,
		/// <summary>A W3C XML Schema <see langword="xs:boolean" /> type.</summary>
		Boolean = 13,
		/// <summary>A W3C XML Schema <see langword="xs:decimal" /> type.</summary>
		Decimal = 14,
		/// <summary>A W3C XML Schema <see langword="xs:float" /> type.</summary>
		Float = 15,
		/// <summary>A W3C XML Schema <see langword="xs:double" /> type.</summary>
		Double = 16,
		/// <summary>A W3C XML Schema <see langword="xs:Duration" /> type.</summary>
		Duration = 17,
		/// <summary>A W3C XML Schema <see langword="xs:dateTime" /> type.</summary>
		DateTime = 18,
		/// <summary>A W3C XML Schema <see langword="xs:time" /> type.</summary>
		Time = 19,
		/// <summary>A W3C XML Schema <see langword="xs:date" /> type.</summary>
		Date = 20,
		/// <summary>A W3C XML Schema <see langword="xs:gYearMonth" /> type.</summary>
		GYearMonth = 21,
		/// <summary>A W3C XML Schema <see langword="xs:gYear" /> type.</summary>
		GYear = 22,
		/// <summary>A W3C XML Schema <see langword="xs:gMonthDay" /> type.</summary>
		GMonthDay = 23,
		/// <summary>A W3C XML Schema <see langword="xs:gDay" /> type.</summary>
		GDay = 24,
		/// <summary>A W3C XML Schema <see langword="xs:gMonth" /> type.</summary>
		GMonth = 25,
		/// <summary>A W3C XML Schema <see langword="xs:hexBinary" /> type.</summary>
		HexBinary = 26,
		/// <summary>A W3C XML Schema <see langword="xs:base64Binary" /> type.</summary>
		Base64Binary = 27,
		/// <summary>A W3C XML Schema <see langword="xs:anyURI" /> type.</summary>
		AnyUri = 28,
		/// <summary>A W3C XML Schema <see langword="xs:QName" /> type.</summary>
		QName = 29,
		/// <summary>A W3C XML Schema <see langword="xs:NOTATION" /> type.</summary>
		Notation = 30,
		/// <summary>A W3C XML Schema <see langword="xs:normalizedString" /> type.</summary>
		NormalizedString = 31,
		/// <summary>A W3C XML Schema <see langword="xs:token" /> type.</summary>
		Token = 32,
		/// <summary>A W3C XML Schema <see langword="xs:language" /> type.</summary>
		Language = 33,
		/// <summary>A W3C XML Schema <see langword="xs:NMTOKEN" /> type.</summary>
		NmToken = 34,
		/// <summary>A W3C XML Schema <see langword="xs:Name" /> type.</summary>
		Name = 35,
		/// <summary>A W3C XML Schema <see langword="xs:NCName" /> type.</summary>
		NCName = 36,
		/// <summary>A W3C XML Schema <see langword="xs:ID" /> type.</summary>
		Id = 37,
		/// <summary>A W3C XML Schema <see langword="xs:IDREF" /> type.</summary>
		Idref = 38,
		/// <summary>A W3C XML Schema <see langword="xs:ENTITY" /> type.</summary>
		Entity = 39,
		/// <summary>A W3C XML Schema <see langword="xs:integer" /> type.</summary>
		Integer = 40,
		/// <summary>A W3C XML Schema <see langword="xs:nonPositiveInteger" /> type.</summary>
		NonPositiveInteger = 41,
		/// <summary>A W3C XML Schema <see langword="xs:negativeInteger" /> type.</summary>
		NegativeInteger = 42,
		/// <summary>A W3C XML Schema <see langword="xs:long" /> type.</summary>
		Long = 43,
		/// <summary>A W3C XML Schema <see langword="xs:int" /> type.</summary>
		Int = 44,
		/// <summary>A W3C XML Schema <see langword="xs:short" /> type.</summary>
		Short = 45,
		/// <summary>A W3C XML Schema <see langword="xs:byte" /> type.</summary>
		Byte = 46,
		/// <summary>A W3C XML Schema <see langword="xs:nonNegativeInteger" /> type.</summary>
		NonNegativeInteger = 47,
		/// <summary>A W3C XML Schema <see langword="xs:unsignedLong" /> type.</summary>
		UnsignedLong = 48,
		/// <summary>A W3C XML Schema <see langword="xs:unsignedInt" /> type.</summary>
		UnsignedInt = 49,
		/// <summary>A W3C XML Schema <see langword="xs:unsignedShort" /> type.</summary>
		UnsignedShort = 50,
		/// <summary>A W3C XML Schema <see langword="xs:unsignedByte" /> type.</summary>
		UnsignedByte = 51,
		/// <summary>A W3C XML Schema <see langword="xs:positiveInteger" /> type.</summary>
		PositiveInteger = 52,
		/// <summary>This value supports the .NET Framework infrastructure and is not intended to be used directly from your code.</summary>
		YearMonthDuration = 53,
		/// <summary>This value supports the .NET Framework infrastructure and is not intended to be used directly from your code.</summary>
		DayTimeDuration = 54
	}
}
