using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using UnityEngine.Bindings;

namespace UnityEngine
{
	[StructLayout(LayoutKind.Sequential, Size = 1)]
	[NativeHeader("Modules/RenderAs2D/Public/RenderAs2DUtil.h")]
	internal struct RenderAs2DUtil
	{
		[MethodImpl(MethodImplOptions.InternalCall)]
		[FreeFunction("RenderAs2DUtil::InitializeCanRenderAs2D")]
		internal static extern void InitializeCanRenderAs2D();

		[MethodImpl(MethodImplOptions.InternalCall)]
		[FreeFunction("RenderAs2DUtil::DisposeCanRenderAs2D")]
		internal static extern void DisposeCanRenderAs2D();
	}
}
