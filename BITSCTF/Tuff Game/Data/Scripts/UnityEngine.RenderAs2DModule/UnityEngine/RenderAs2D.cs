using System;
using System.Runtime.CompilerServices;
using UnityEngine.Bindings;

namespace UnityEngine
{
	[NativeType(Header = "Modules/RenderAs2D/Public/RenderAs2D.h")]
	[RequireComponent(typeof(Transform))]
	[AddComponentMenu("")]
	internal sealed class RenderAs2D : Renderer
	{
		internal void Init(Component owner)
		{
			IntPtr intPtr = MarshalledUnityObject.MarshalNotNull(this);
			if (intPtr == (IntPtr)0)
			{
				ThrowHelper.ThrowNullReferenceException(this);
			}
			Init_Injected(intPtr, MarshalledUnityObject.Marshal(owner));
		}

		internal bool IsOwner(Component owner)
		{
			IntPtr intPtr = MarshalledUnityObject.MarshalNotNull(this);
			if (intPtr == (IntPtr)0)
			{
				ThrowHelper.ThrowNullReferenceException(this);
			}
			return IsOwner_Injected(intPtr, MarshalledUnityObject.Marshal(owner));
		}

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern void Init_Injected(IntPtr _unity_self, IntPtr owner);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern bool IsOwner_Injected(IntPtr _unity_self, IntPtr owner);
	}
}
