using System;
using UnityEngine.Bindings;
using UnityEngine.Scripting;

namespace UnityEngine.TextCore.LowLevel
{
	[Serializable]
	[UsedByNativeCode]
	internal struct MarkAdjustmentRecord
	{
		[NativeName("anchorPoint")]
		[SerializeField]
		private GlyphAnchorPoint m_AnchorPoint;

		[SerializeField]
		[NativeName("markPositionAdjustment")]
		private MarkPositionAdjustment m_MarkPositionAdjustment;

		public GlyphAnchorPoint anchorPosition
		{
			get
			{
				return m_AnchorPoint;
			}
			set
			{
				m_AnchorPoint = value;
			}
		}

		public MarkPositionAdjustment markPositionAdjustment
		{
			get
			{
				return m_MarkPositionAdjustment;
			}
			set
			{
				m_MarkPositionAdjustment = value;
			}
		}
	}
}
