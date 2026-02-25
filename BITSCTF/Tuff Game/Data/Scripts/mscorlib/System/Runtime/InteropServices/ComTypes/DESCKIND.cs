namespace System.Runtime.InteropServices.ComTypes
{
	/// <summary>Identifies the type description being bound to.</summary>
	[Serializable]
	public enum DESCKIND
	{
		/// <summary>Indicates that no match was found.</summary>
		DESCKIND_NONE = 0,
		/// <summary>Indicates that a <see cref="T:System.Runtime.InteropServices.FUNCDESC" /> structure was returned.</summary>
		DESCKIND_FUNCDESC = 1,
		/// <summary>Indicates that a <see langword="VARDESC" /> was returned.</summary>
		DESCKIND_VARDESC = 2,
		/// <summary>Indicates that a <see langword="TYPECOMP" /> was returned.</summary>
		DESCKIND_TYPECOMP = 3,
		/// <summary>Indicates that an <see langword="IMPLICITAPPOBJ" /> was returned.</summary>
		DESCKIND_IMPLICITAPPOBJ = 4,
		/// <summary>Indicates an end-of-enumeration marker.</summary>
		DESCKIND_MAX = 5
	}
}
