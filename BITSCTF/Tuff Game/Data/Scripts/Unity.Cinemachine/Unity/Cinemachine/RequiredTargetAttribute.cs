using System;

namespace Unity.Cinemachine
{
	public sealed class RequiredTargetAttribute : Attribute
	{
		public enum RequiredTargets
		{
			None = 0,
			Tracking = 1,
			LookAt = 2,
			GroupLookAt = 3
		}

		public RequiredTargets RequiredTarget { get; private set; }

		public RequiredTargetAttribute(RequiredTargets requiredTarget)
		{
			RequiredTarget = requiredTarget;
		}
	}
}
