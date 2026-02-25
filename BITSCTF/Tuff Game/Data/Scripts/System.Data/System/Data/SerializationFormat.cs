namespace System.Data
{
	/// <summary>Determines the serialization format for a <see cref="T:System.Data.DataSet" />.</summary>
	public enum SerializationFormat
	{
		/// <summary>Serialize as XML content. The default.</summary>
		Xml = 0,
		/// <summary>Serialize as binary content. Available in ADO.NET 2.0 only.</summary>
		Binary = 1
	}
}
