namespace System.Xml.XPath
{
	/// <summary>Defines the XPath node types that can be returned from the <see cref="T:System.Xml.XPath.XPathNavigator" /> class.</summary>
	public enum XPathNodeType
	{
		/// <summary>The root node of the XML document or node tree.</summary>
		Root = 0,
		/// <summary>An element, such as &lt;element&gt;.</summary>
		Element = 1,
		/// <summary>An attribute, such as id='123'.</summary>
		Attribute = 2,
		/// <summary>A namespace, such as xmlns="namespace".</summary>
		Namespace = 3,
		/// <summary>The text content of a node. Equivalent to the Document Object Model (DOM) Text and CDATA node types. Contains at least one character.</summary>
		Text = 4,
		/// <summary>A node with white space characters and xml:space set to preserve.</summary>
		SignificantWhitespace = 5,
		/// <summary>A node with only white space characters and no significant white space. White space characters are #x20, #x9, #xD, or #xA.</summary>
		Whitespace = 6,
		/// <summary>A processing instruction, such as &lt;?pi test?&gt;. This does not include XML declarations, which are not visible to the <see cref="T:System.Xml.XPath.XPathNavigator" /> class. </summary>
		ProcessingInstruction = 7,
		/// <summary>A comment, such as &lt;!-- my comment --&gt;</summary>
		Comment = 8,
		/// <summary>Any of the <see cref="T:System.Xml.XPath.XPathNodeType" /> node types.</summary>
		All = 9
	}
}
