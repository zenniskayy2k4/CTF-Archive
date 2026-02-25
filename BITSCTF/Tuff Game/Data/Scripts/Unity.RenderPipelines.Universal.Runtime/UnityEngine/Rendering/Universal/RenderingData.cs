namespace UnityEngine.Rendering.Universal
{
	public struct RenderingData
	{
		internal ContextContainer frameData;

		public CameraData cameraData;

		public LightData lightData;

		public ShadowData shadowData;

		public PostProcessingData postProcessingData;

		internal UniversalRenderingData universalRenderingData => frameData.Get<UniversalRenderingData>();

		public ref CullingResults cullResults => ref frameData.Get<UniversalRenderingData>().cullResults;

		public ref bool supportsDynamicBatching => ref frameData.Get<UniversalRenderingData>().supportsDynamicBatching;

		public ref PerObjectData perObjectData => ref frameData.Get<UniversalRenderingData>().perObjectData;

		public ref bool postProcessingEnabled => ref frameData.Get<UniversalPostProcessingData>().isEnabled;

		internal RenderingData(ContextContainer frameData)
		{
			this.frameData = frameData;
			cameraData = new CameraData(frameData);
			lightData = new LightData(frameData);
			shadowData = new ShadowData(frameData);
			postProcessingData = new PostProcessingData(frameData);
		}
	}
}
