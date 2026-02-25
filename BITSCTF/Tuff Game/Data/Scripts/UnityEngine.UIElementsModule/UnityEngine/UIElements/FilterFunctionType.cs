using System;

namespace UnityEngine.UIElements
{
	[Serializable]
	public enum FilterFunctionType
	{
		None = 0,
		Custom = 1,
		Tint = 2,
		Opacity = 3,
		Invert = 4,
		Grayscale = 5,
		Sepia = 6,
		Blur = 7,
		Contrast = 8,
		HueRotate = 9,
		[Obsolete("Use Enum.GetValues(typeof(FilterFunctionType)).Length instead", false)]
		Count = 10
	}
}
