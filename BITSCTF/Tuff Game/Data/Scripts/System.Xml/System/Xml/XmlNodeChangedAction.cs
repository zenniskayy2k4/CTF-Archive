namespace System.Xml
{
	/// <summary>Specifies the type of node change.</summary>
	public enum XmlNodeChangedAction
	{
		/// <summary>A node is being inserted in the tree.</summary>
		Insert = 0,
		/// <summary>A node is being removed from the tree.</summary>
		Remove = 1,
		/// <summary>A node value is being changed.</summary>
		Change = 2
	}
}
