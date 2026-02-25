using System;
using System.Diagnostics;

namespace UnityEngine.Rendering.UnifiedRayTracing
{
	internal static class Utils
	{
		public static void Destroy(Object obj)
		{
			if (obj != null)
			{
				Object.Destroy(obj);
			}
		}

		[Conditional("UNITY_ASSERTIONS")]
		public static void CheckArgIsNotNull(object obj, string argName)
		{
			if (obj == null)
			{
				throw new ArgumentNullException(argName);
			}
		}

		[Conditional("UNITY_ASSERTIONS")]
		public static void CheckArg(bool condition, string message)
		{
			if (!condition)
			{
				throw new ArgumentException(message);
			}
		}

		[Conditional("UNITY_ASSERTIONS")]
		public static void CheckArgRange<T>(T value, T minIncluded, T maxExcluded, string argName) where T : IComparable
		{
			if (value.CompareTo(minIncluded) < 0 || value.CompareTo(maxExcluded) >= 0)
			{
				string message = $"{argName}={value}, it must be in the range [{minIncluded}, {maxExcluded}[";
				throw new ArgumentOutOfRangeException(argName, message);
			}
		}
	}
}
