using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using UnityEngine.Bindings;
using UnityEngine.Scripting.APIUpdating;

namespace UnityEngine.AI
{
	[MovedFrom("UnityEngine")]
	[NativeHeader("Modules/AI/Components/OffMeshLink.bindings.h")]
	public struct OffMeshLinkData
	{
		internal int m_Valid;

		internal int m_Activated;

		internal EntityId m_InstanceID;

		internal OffMeshLinkType m_LinkType;

		internal Vector3 m_StartPos;

		internal Vector3 m_EndPos;

		public bool valid => m_Valid != 0;

		public bool activated => m_Activated != 0;

		public OffMeshLinkType linkType => m_LinkType;

		public Vector3 startPos => m_StartPos;

		public Vector3 endPos => m_EndPos;

		public Object owner => GetLinkOwnerInternal(m_InstanceID);

		[Obsolete("offMeshLink has been deprecated. Use 'owner' instead.")]
		public OffMeshLink offMeshLink => GetOffMeshLinkInternal(m_InstanceID);

		[FreeFunction("OffMeshLinkScriptBindings::GetLinkOwnerInternal")]
		private static Object GetLinkOwnerInternal(EntityId instanceID)
		{
			return Unmarshal.UnmarshalUnityObject<Object>(GetLinkOwnerInternal_Injected(ref instanceID));
		}

		[FreeFunction("OffMeshLinkScriptBindings::GetOffMeshLinkInternal")]
		private static OffMeshLink GetOffMeshLinkInternal(EntityId instanceID)
		{
			return Unmarshal.UnmarshalUnityObject<OffMeshLink>(GetOffMeshLinkInternal_Injected(ref instanceID));
		}

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern IntPtr GetLinkOwnerInternal_Injected([In] ref EntityId instanceID);

		[MethodImpl(MethodImplOptions.InternalCall)]
		private static extern IntPtr GetOffMeshLinkInternal_Injected([In] ref EntityId instanceID);
	}
}
