namespace UnityEngine.Rendering.Universal
{
	public class UniversalRenderingData : ContextItem
	{
		public CullingResults cullResults;

		public bool supportsDynamicBatching;

		public PerObjectData perObjectData;

		public RenderingMode renderingMode { get; internal set; }

		public LayerMask prepassLayerMask { get; internal set; }

		public LayerMask opaqueLayerMask { get; internal set; }

		public LayerMask transparentLayerMask { get; internal set; }

		public bool stencilLodCrossFadeEnabled { get; internal set; }

		public override void Reset()
		{
			cullResults = default(CullingResults);
			supportsDynamicBatching = false;
			perObjectData = PerObjectData.None;
			renderingMode = RenderingMode.Forward;
			stencilLodCrossFadeEnabled = false;
			prepassLayerMask = -1;
			opaqueLayerMask = -1;
			transparentLayerMask = -1;
		}
	}
}
