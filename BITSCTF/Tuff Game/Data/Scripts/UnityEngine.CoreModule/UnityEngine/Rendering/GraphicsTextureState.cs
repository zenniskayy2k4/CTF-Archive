using UnityEngine.Bindings;
using UnityEngine.Scripting;

namespace UnityEngine.Rendering
{
	[NativeType("Runtime/Export/Graphics/GraphicsTexture.bindings.h")]
	[UsedByNativeCode]
	public enum GraphicsTextureState
	{
		Constructed = 0,
		Initializing = 1,
		InitializedOnRenderThread = 2,
		DestroyQueued = 3,
		Destroyed = 4
	}
}
