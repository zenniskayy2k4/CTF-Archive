using System;
using System.Runtime.InteropServices;
using UnityEngine.Internal;
using UnityEngine.Scripting;

namespace UnityEngine.Analytics
{
	[Serializable]
	[StructLayout(LayoutKind.Sequential)]
	[RequiredByNativeCode(GenerateProxy = true)]
	[ExcludeFromDocs]
	public class SubsystemsAnalyticStart : SubsystemsAnalyticBase
	{
		public SubsystemsAnalyticStart()
			: base("SubsystemStart")
		{
		}

		[RequiredByNativeCode]
		internal static SubsystemsAnalyticStart CreateSubsystemsAnalyticStart()
		{
			return new SubsystemsAnalyticStart();
		}
	}
}
