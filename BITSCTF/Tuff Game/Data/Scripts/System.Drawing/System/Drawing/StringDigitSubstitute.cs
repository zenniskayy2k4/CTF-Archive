namespace System.Drawing
{
	/// <summary>The <see cref="T:System.Drawing.StringDigitSubstitute" /> enumeration specifies how to substitute digits in a string according to a user's locale or language.</summary>
	public enum StringDigitSubstitute
	{
		/// <summary>Specifies a user-defined substitution scheme.</summary>
		User = 0,
		/// <summary>Specifies to disable substitutions.</summary>
		None = 1,
		/// <summary>Specifies substitution digits that correspond with the official national language of the user's locale.</summary>
		National = 2,
		/// <summary>Specifies substitution digits that correspond with the user's native script or language, which may be different from the official national language of the user's locale.</summary>
		Traditional = 3
	}
}
