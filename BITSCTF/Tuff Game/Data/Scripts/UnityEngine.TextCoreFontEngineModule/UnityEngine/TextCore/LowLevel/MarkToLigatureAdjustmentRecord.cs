using System;
using UnityEngine.Bindings;
using UnityEngine.Scripting;

namespace UnityEngine.TextCore.LowLevel
{
	[Serializable]
	[UsedByNativeCode]
	internal struct MarkToLigatureAdjustmentRecord
	{
		[NativeName("ligatureGlyphID")]
		[SerializeField]
		private uint m_LigatureGlyphID;

		[SerializeField]
		[NativeName("combiningMarkGlyphID")]
		private uint m_CombiningMarkGlyphID;

		[SerializeField]
		[NativeName("adjustmentRecords")]
		private MarkAdjustmentRecord[] m_CombiningMarkAdjustmentRecords;

		public uint ligatureGlyphID
		{
			get
			{
				return m_LigatureGlyphID;
			}
			set
			{
				m_LigatureGlyphID = value;
			}
		}

		public uint combiningMarkGlyphID
		{
			get
			{
				return m_CombiningMarkGlyphID;
			}
			set
			{
				m_CombiningMarkGlyphID = value;
			}
		}

		public MarkAdjustmentRecord[] combiningMarkAdjustmentRecords
		{
			get
			{
				return m_CombiningMarkAdjustmentRecords;
			}
			set
			{
				m_CombiningMarkAdjustmentRecords = value;
			}
		}
	}
}
