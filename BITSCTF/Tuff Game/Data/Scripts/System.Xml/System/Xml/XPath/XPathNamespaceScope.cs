namespace System.Xml.XPath
{
	/// <summary>Defines the namespace scope.</summary>
	public enum XPathNamespaceScope
	{
		/// <summary>Returns all namespaces defined in the scope of the current node. This includes the xmlns:xml namespace which is always declared implicitly. The order of the namespaces returned is not defined.</summary>
		All = 0,
		/// <summary>Returns all namespaces defined in the scope of the current node, excluding the xmlns:xml namespace. The xmlns:xml namespace is always declared implicitly. The order of the namespaces returned is not defined.</summary>
		ExcludeXml = 1,
		/// <summary>Returns all namespaces that are defined locally at the current node. </summary>
		Local = 2
	}
}
