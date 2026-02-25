namespace System.Drawing.Drawing2D
{
	/// <summary>Specifies the style of dashed lines drawn with a <see cref="T:System.Drawing.Pen" /> object.</summary>
	public enum DashStyle
	{
		/// <summary>Specifies a solid line.</summary>
		Solid = 0,
		/// <summary>Specifies a line consisting of dashes.</summary>
		Dash = 1,
		/// <summary>Specifies a line consisting of dots.</summary>
		Dot = 2,
		/// <summary>Specifies a line consisting of a repeating pattern of dash-dot.</summary>
		DashDot = 3,
		/// <summary>Specifies a line consisting of a repeating pattern of dash-dot-dot.</summary>
		DashDotDot = 4,
		/// <summary>Specifies a user-defined custom dash style.</summary>
		Custom = 5
	}
}
