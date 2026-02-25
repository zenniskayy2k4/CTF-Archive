using System;

namespace UnityEngine.Rendering
{
	public enum OpenGLESVersion
	{
		None = 0,
		[Obsolete("OpenGL ES 2.0 is no longer supported in Unity 2023.1")]
		OpenGLES20 = 1,
		OpenGLES30 = 2,
		OpenGLES31 = 3,
		OpenGLES31AEP = 4,
		OpenGLES32 = 5
	}
}
