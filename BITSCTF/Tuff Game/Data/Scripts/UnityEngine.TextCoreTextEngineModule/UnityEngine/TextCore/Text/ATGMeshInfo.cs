using System;
using UnityEngine.Bindings;

namespace UnityEngine.TextCore.Text
{
	[NativeHeader("Modules/TextCoreTextEngine/Native/ATGMeshInfo.h")]
	[VisibleToOtherModules(new string[] { "UnityEngine.UIElementsModule" })]
	internal struct ATGMeshInfo
	{
		private IntPtr m_TextElementInfosPtr;

		private int m_TextElementCount;

		public int textAssetId;

		public unsafe Span<NativeTextElementInfo> textElementInfos
		{
			get
			{
				if (m_TextElementInfosPtr == IntPtr.Zero || m_TextElementCount == 0)
				{
					return default(Span<NativeTextElementInfo>);
				}
				return new Span<NativeTextElementInfo>(m_TextElementInfosPtr.ToPointer(), m_TextElementCount);
			}
		}
	}
}
