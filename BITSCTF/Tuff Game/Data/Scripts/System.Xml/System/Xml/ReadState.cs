namespace System.Xml
{
	/// <summary>Specifies the state of the reader.</summary>
	public enum ReadState
	{
		/// <summary>The <see langword="Read" /> method has not been called.</summary>
		Initial = 0,
		/// <summary>The <see langword="Read" /> method has been called. Additional methods may be called on the reader.</summary>
		Interactive = 1,
		/// <summary>An error occurred that prevents the read operation from continuing.</summary>
		Error = 2,
		/// <summary>The end of the file has been reached successfully.</summary>
		EndOfFile = 3,
		/// <summary>The <see cref="M:System.Xml.XmlReader.Close" /> method has been called.</summary>
		Closed = 4
	}
}
