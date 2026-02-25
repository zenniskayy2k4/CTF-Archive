using System;
using UnityEngine.Bindings;
using UnityEngine.Scripting;

namespace UnityEngine
{
	[AttributeUsage(AttributeTargets.Class | AttributeTargets.Interface, Inherited = true)]
	[VisibleToOtherModules(new string[] { "UnityEditor.UIBuilderModule" })]
	[RequiredByNativeCode]
	internal sealed class ExtensionOfNativeClassAttribute : Attribute
	{
	}
}
