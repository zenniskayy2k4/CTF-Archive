namespace System.Drawing.Drawing2D
{
	/// <summary>Specifies the overall quality when rendering GDI+ objects.</summary>
	public enum QualityMode
	{
		/// <summary>Specifies an invalid mode.</summary>
		Invalid = -1,
		/// <summary>Specifies the default mode.</summary>
		Default = 0,
		/// <summary>Specifies low quality, high speed rendering.</summary>
		Low = 1,
		/// <summary>Specifies high quality, low speed rendering.</summary>
		High = 2
	}
}
