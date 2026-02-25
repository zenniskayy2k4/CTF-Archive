using UnityEngine.Bindings;

namespace UnityEngine.UIElements
{
	[VisibleToOtherModules(new string[] { "UnityEditor.UIBuilderModule" })]
	internal enum StyleValueFunction
	{
		Unknown = 0,
		Var = 1,
		Env = 2,
		LinearGradient = 3,
		NoneFilter = 4,
		CustomFilter = 5,
		FilterTint = 6,
		FilterOpacity = 7,
		FilterInvert = 8,
		FilterGrayscale = 9,
		FilterSepia = 10,
		FilterBlur = 11,
		FilterContrast = 12,
		FilterHueRotate = 13,
		MaterialProperty = 14
	}
}
