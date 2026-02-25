namespace System.ComponentModel.Composition
{
	/// <summary>Specifies values that indicate how the MEF composition engine searches for imports.</summary>
	public enum ImportSource
	{
		/// <summary>Imports may be satisfied from the current scope or any ancestor scope.</summary>
		Any = 0,
		/// <summary>Imports may be satisfied only from the current scope.</summary>
		Local = 1,
		/// <summary>Imports may be satisfied only from an ancestor scope.</summary>
		NonLocal = 2
	}
}
