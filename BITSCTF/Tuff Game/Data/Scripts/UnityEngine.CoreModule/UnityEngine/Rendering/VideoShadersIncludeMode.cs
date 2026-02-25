namespace UnityEngine.Rendering
{
	public enum VideoShadersIncludeMode
	{
		[InspectorName("Don't include")]
		Never = 0,
		[InspectorName("Include if referenced")]
		Referenced = 1,
		[InspectorName("Always include")]
		Always = 2
	}
}
