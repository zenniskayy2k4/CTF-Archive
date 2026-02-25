using System;
using System.Collections.Generic;
using System.Linq;

namespace UnityEngine.NVIDIA
{
	public class GraphicsDeviceDebugView
	{
		internal const int MaxFeatures = 16;

		internal uint m_ViewId = 0u;

		internal uint m_DeviceVersion = 0u;

		internal uint m_NgxVersion = 0u;

		internal readonly DLSSDebugFeatureInfos[] m_DlssDebugFeatures = new DLSSDebugFeatureInfos[16];

		internal uint m_DlssFeatureValidCount = 0u;

		public uint deviceVersion => m_DeviceVersion;

		public uint ngxVersion => m_NgxVersion;

		[Obsolete("This property causes garbage collection and is inefficient. Use dlssFeatureInfosSpan and dlssFeatureInfoCount instead.", false)]
		public IEnumerable<DLSSDebugFeatureInfos> dlssFeatureInfos => m_DlssDebugFeatures.Take((int)m_DlssFeatureValidCount);

		public ReadOnlySpan<DLSSDebugFeatureInfos> dlssFeatureInfosSpan => new ReadOnlySpan<DLSSDebugFeatureInfos>(m_DlssDebugFeatures, 0, (int)m_DlssFeatureValidCount);

		internal GraphicsDeviceDebugView(uint viewId)
		{
			m_ViewId = viewId;
		}
	}
}
