using System;

namespace UnityEngine.SocialPlatforms
{
	[Obsolete("Range is deprecated and will be removed in a future release.", false)]
	public struct Range
	{
		public int from;

		public int count;

		public Range(int fromValue, int valueCount)
		{
			from = fromValue;
			count = valueCount;
		}
	}
}
