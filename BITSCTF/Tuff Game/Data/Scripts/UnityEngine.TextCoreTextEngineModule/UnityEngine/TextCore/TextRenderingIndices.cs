using UnityEngine.Bindings;

namespace UnityEngine.TextCore
{
	[VisibleToOtherModules(new string[] { "UnityEngine.UIElementsModule" })]
	[NativeHeader("Modules/TextCoreTextEngine/Native/TextRenderingIndices.h")]
	internal struct TextRenderingIndices
	{
		public int meshIndex;

		public int textElementInfoIndex;
	}
}
