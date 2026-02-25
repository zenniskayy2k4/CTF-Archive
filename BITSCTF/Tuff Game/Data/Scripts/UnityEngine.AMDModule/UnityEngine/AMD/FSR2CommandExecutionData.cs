namespace UnityEngine.AMD
{
	public struct FSR2CommandExecutionData
	{
		internal enum Textures
		{
			ColorInput = 0,
			ColorOutput = 1,
			Depth = 2,
			MotionVectors = 3,
			TransparencyMask = 4,
			ExposureTexture = 5,
			ReactiveMask = 6,
			BiasColorMask = 7
		}

		public float jitterOffsetX;

		public float jitterOffsetY;

		public float MVScaleX;

		public float MVScaleY;

		public uint renderSizeWidth;

		public uint renderSizeHeight;

		public int enableSharpening;

		public float sharpness;

		public float frameTimeDelta;

		public float preExposure;

		public int reset;

		public float cameraNear;

		public float cameraFar;

		public float cameraFovAngleVertical;

		internal uint featureSlot;
	}
}
