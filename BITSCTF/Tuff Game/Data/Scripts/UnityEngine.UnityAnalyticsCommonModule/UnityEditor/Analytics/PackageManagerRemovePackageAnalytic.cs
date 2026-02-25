using System;
using System.Runtime.InteropServices;
using UnityEngine.Internal;
using UnityEngine.Scripting;

namespace UnityEditor.Analytics
{
	[Serializable]
	[StructLayout(LayoutKind.Sequential)]
	[ExcludeFromDocs]
	[RequiredByNativeCode(GenerateProxy = true)]
	public class PackageManagerRemovePackageAnalytic : PackageManagerBaseAnalytic
	{
		public PackageManagerRemovePackageAnalytic()
			: base("removePackage")
		{
		}

		[RequiredByNativeCode]
		internal static PackageManagerRemovePackageAnalytic CreatePackageManagerRemovePackageAnalytic()
		{
			return new PackageManagerRemovePackageAnalytic();
		}
	}
}
