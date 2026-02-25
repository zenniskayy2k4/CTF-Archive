namespace System.Drawing.Imaging
{
	/// <summary>Specifies which GDI+ objects use color adjustment information.</summary>
	public enum ColorAdjustType
	{
		/// <summary>Color adjustment information that is used by all GDI+ objects that do not have their own color adjustment information.</summary>
		Default = 0,
		/// <summary>Color adjustment information for <see cref="T:System.Drawing.Bitmap" /> objects.</summary>
		Bitmap = 1,
		/// <summary>Color adjustment information for <see cref="T:System.Drawing.Brush" /> objects.</summary>
		Brush = 2,
		/// <summary>Color adjustment information for <see cref="T:System.Drawing.Pen" /> objects.</summary>
		Pen = 3,
		/// <summary>Color adjustment information for text.</summary>
		Text = 4,
		/// <summary>The number of types specified.</summary>
		Count = 5,
		/// <summary>The number of types specified.</summary>
		Any = 6
	}
}
