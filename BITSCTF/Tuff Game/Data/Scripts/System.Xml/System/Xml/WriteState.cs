namespace System.Xml
{
	/// <summary>Specifies the state of the <see cref="T:System.Xml.XmlWriter" />.</summary>
	public enum WriteState
	{
		/// <summary>Indicates that a Write method has not yet been called.</summary>
		Start = 0,
		/// <summary>Indicates that the prolog is being written.</summary>
		Prolog = 1,
		/// <summary>Indicates that an element start tag is being written.</summary>
		Element = 2,
		/// <summary>Indicates that an attribute value is being written.</summary>
		Attribute = 3,
		/// <summary>Indicates that element content is being written.</summary>
		Content = 4,
		/// <summary>Indicates that the <see cref="M:System.Xml.XmlWriter.Close" /> method has been called.</summary>
		Closed = 5,
		/// <summary>An exception has been thrown, which has left the <see cref="T:System.Xml.XmlWriter" /> in an invalid state. You can call the <see cref="M:System.Xml.XmlWriter.Close" /> method to put the <see cref="T:System.Xml.XmlWriter" /> in the <see cref="F:System.Xml.WriteState.Closed" /> state. Any other <see cref="T:System.Xml.XmlWriter" /> method calls results in an <see cref="T:System.InvalidOperationException" />.</summary>
		Error = 6
	}
}
