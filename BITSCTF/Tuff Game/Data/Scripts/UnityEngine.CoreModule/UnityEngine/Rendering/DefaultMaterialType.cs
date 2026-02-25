using UnityEngine.Bindings;

namespace UnityEngine.Rendering
{
	[VisibleToOtherModules]
	internal enum DefaultMaterialType
	{
		Default = 0,
		Particle = 1,
		Line = 2,
		Terrain = 3,
		Sprite = 4,
		SpriteMask = 5,
		UGUI = 6,
		UGUI_Overdraw = 7,
		UGUI_ETC1Supported = 8
	}
}
