namespace System.Xml
{
	/// <summary>Specifies the type of node.</summary>
	public enum XmlNodeType
	{
		/// <summary>This is returned by the <see cref="T:System.Xml.XmlReader" /> if a <see langword="Read" /> method has not been called.</summary>
		None = 0,
		/// <summary>An element (for example, &lt;item&gt; ).</summary>
		Element = 1,
		/// <summary>An attribute (for example, id='123' ).</summary>
		Attribute = 2,
		/// <summary>The text content of a node.</summary>
		Text = 3,
		/// <summary>A CDATA section (for example, &lt;![CDATA[my escaped text]]&gt; ).</summary>
		CDATA = 4,
		/// <summary>A reference to an entity (for example, &amp;num; ).</summary>
		EntityReference = 5,
		/// <summary>An entity declaration (for example, &lt;!ENTITY...&gt; ).</summary>
		Entity = 6,
		/// <summary>A processing instruction (for example, &lt;?pi test?&gt; ).</summary>
		ProcessingInstruction = 7,
		/// <summary>A comment (for example, &lt;!-- my comment --&gt; ).</summary>
		Comment = 8,
		/// <summary>A document object that, as the root of the document tree, provides access to the entire XML document.</summary>
		Document = 9,
		/// <summary>The document type declaration, indicated by the following tag (for example, &lt;!DOCTYPE...&gt; ).</summary>
		DocumentType = 10,
		/// <summary>A document fragment.</summary>
		DocumentFragment = 11,
		/// <summary>A notation in the document type declaration (for example, &lt;!NOTATION...&gt; ).</summary>
		Notation = 12,
		/// <summary>White space between markup.</summary>
		Whitespace = 13,
		/// <summary>White space between markup in a mixed content model or white space within the xml:space="preserve" scope.</summary>
		SignificantWhitespace = 14,
		/// <summary>An end element tag (for example, &lt;/item&gt; ).</summary>
		EndElement = 15,
		/// <summary>Returned when <see langword="XmlReader" /> gets to the end of the entity replacement as a result of a call to <see cref="M:System.Xml.XmlReader.ResolveEntity" />.</summary>
		EndEntity = 16,
		/// <summary>The XML declaration (for example, &lt;?xml version='1.0'?&gt; ).</summary>
		XmlDeclaration = 17
	}
}
