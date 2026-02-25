using System;
using UnityEngine.Bindings;
using UnityEngine.Scripting;

namespace UnityEngine.TextCore.LowLevel
{
	[Serializable]
	[UsedByNativeCode]
	internal struct GlyphIDSequence
	{
		[NativeName("glyphIDs")]
		[SerializeField]
		private uint[] m_GlyphIDs;

		public uint[] glyphIDs
		{
			get
			{
				return m_GlyphIDs;
			}
			set
			{
				m_GlyphIDs = value;
			}
		}
	}
}
