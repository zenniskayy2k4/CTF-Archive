using System;

namespace UnityEngine.Rendering.Universal
{
	[Serializable]
	public sealed class BloomFilterModeParameter : VolumeParameter<BloomFilterMode>
	{
		public BloomFilterModeParameter(BloomFilterMode value, bool overrideState = false)
			: base(value, overrideState)
		{
		}
	}
}
