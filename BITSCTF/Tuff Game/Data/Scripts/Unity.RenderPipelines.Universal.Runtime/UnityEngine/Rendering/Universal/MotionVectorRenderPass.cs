using UnityEngine.Experimental.Rendering;
using UnityEngine.Rendering.RenderGraphModule;

namespace UnityEngine.Rendering.Universal
{
	internal sealed class MotionVectorRenderPass : ScriptableRenderPass
	{
		private class PassData
		{
			internal Camera camera;

			internal XRPass xr;

			internal TextureHandle cameraDepth;

			internal Material cameraMaterial;

			internal RendererListHandle rendererListHdl;

			internal RendererList rendererList;
		}

		public class MotionMatrixPassData
		{
			public MotionVectorsPersistentData motionData;

			public XRPass xr;
		}

		internal const string k_MotionVectorTextureName = "_MotionVectorTexture";

		internal const string k_MotionVectorDepthTextureName = "_MotionVectorDepthTexture";

		internal const GraphicsFormat k_TargetFormat = GraphicsFormat.R16G16_SFloat;

		public const string k_MotionVectorsLightModeTag = "MotionVectors";

		private static readonly string[] s_ShaderTags = new string[1] { "MotionVectors" };

		private static readonly int s_CameraDepthTextureID = Shader.PropertyToID("_CameraDepthTexture");

		private static readonly ProfilingSampler s_SetMotionMatrixProfilingSampler = new ProfilingSampler("Set Motion Vector Global Matrices");

		private readonly Material m_CameraMaterial;

		private readonly FilteringSettings m_FilteringSettings;

		internal MotionVectorRenderPass(RenderPassEvent evt, Material cameraMaterial, LayerMask opaqueLayerMask)
		{
			base.profilingSampler = ProfilingSampler.Get(URPProfileId.DrawMotionVectors);
			base.renderPassEvent = evt;
			m_CameraMaterial = cameraMaterial;
			m_FilteringSettings = new FilteringSettings(RenderQueueRange.opaque, opaqueLayerMask);
			ConfigureInput(ScriptableRenderPassInput.Depth);
		}

		private static void ExecutePass(RasterCommandBuffer cmd, PassData passData, RendererList rendererList)
		{
			Material cameraMaterial = passData.cameraMaterial;
			if (!(cameraMaterial == null))
			{
				Camera camera = passData.camera;
				if (camera.cameraType != CameraType.Preview)
				{
					camera.depthTextureMode |= DepthTextureMode.Depth | DepthTextureMode.MotionVectors;
					DrawCameraMotionVectors(cmd, passData.xr, cameraMaterial);
					DrawObjectMotionVectors(cmd, passData.xr, ref rendererList);
				}
			}
		}

		private static DrawingSettings GetDrawingSettings(Camera camera, bool supportsDynamicBatching)
		{
			SortingSettings sortingSettings = new SortingSettings(camera);
			sortingSettings.criteria = SortingCriteria.CommonOpaque;
			SortingSettings sortingSettings2 = sortingSettings;
			DrawingSettings drawingSettings = new DrawingSettings(ShaderTagId.none, sortingSettings2);
			drawingSettings.perObjectData = PerObjectData.MotionVectors;
			drawingSettings.enableDynamicBatching = supportsDynamicBatching;
			drawingSettings.enableInstancing = true;
			drawingSettings.lodCrossFadeStencilMask = 0;
			DrawingSettings result = drawingSettings;
			for (int i = 0; i < s_ShaderTags.Length; i++)
			{
				result.SetShaderPassName(i, new ShaderTagId(s_ShaderTags[i]));
			}
			return result;
		}

		private static void DrawCameraMotionVectors(RasterCommandBuffer cmd, XRPass xr, Material cameraMaterial)
		{
			bool supportsFoveatedRendering = xr.supportsFoveatedRendering;
			bool flag = supportsFoveatedRendering && XRSystem.foveatedRenderingCaps.HasFlag(FoveatedRenderingCaps.NonUniformRaster);
			if (supportsFoveatedRendering)
			{
				if (flag)
				{
					cmd.SetFoveatedRenderingMode(FoveatedRenderingMode.Disabled);
				}
				else
				{
					cmd.SetFoveatedRenderingMode(FoveatedRenderingMode.Enabled);
				}
			}
			cmd.DrawProcedural(Matrix4x4.identity, cameraMaterial, 0, MeshTopology.Triangles, 3, 1);
			if (supportsFoveatedRendering && !flag)
			{
				cmd.SetFoveatedRenderingMode(FoveatedRenderingMode.Disabled);
			}
		}

		private static void DrawObjectMotionVectors(RasterCommandBuffer cmd, XRPass xr, ref RendererList rendererList)
		{
			bool supportsFoveatedRendering = xr.supportsFoveatedRendering;
			if (supportsFoveatedRendering)
			{
				cmd.SetFoveatedRenderingMode(FoveatedRenderingMode.Enabled);
			}
			cmd.DrawRendererList(rendererList);
			if (supportsFoveatedRendering)
			{
				cmd.SetFoveatedRenderingMode(FoveatedRenderingMode.Disabled);
			}
		}

		private void InitPassData(ref PassData passData, UniversalCameraData cameraData)
		{
			passData.camera = cameraData.camera;
			passData.xr = cameraData.xr;
			passData.cameraMaterial = m_CameraMaterial;
		}

		private void InitRendererLists(ref PassData passData, ref CullingResults cullResults, bool supportsDynamicBatching, ScriptableRenderContext context, RenderGraph renderGraph, bool useRenderGraph)
		{
			DrawingSettings drawingSettings = GetDrawingSettings(passData.camera, supportsDynamicBatching);
			RenderStateBlock rsb = new RenderStateBlock(RenderStateMask.Nothing);
			if (useRenderGraph)
			{
				RenderingUtils.CreateRendererListWithRenderStateBlock(renderGraph, ref cullResults, drawingSettings, m_FilteringSettings, rsb, ref passData.rendererListHdl);
			}
			else
			{
				RenderingUtils.CreateRendererListWithRenderStateBlock(context, ref cullResults, drawingSettings, m_FilteringSettings, rsb, ref passData.rendererList);
			}
		}

		internal void Render(RenderGraph renderGraph, ContextContainer frameData, TextureHandle cameraDepthTexture, TextureHandle motionVectorColor, TextureHandle motionVectorDepth)
		{
			UniversalRenderingData universalRenderingData = frameData.Get<UniversalRenderingData>();
			UniversalCameraData universalCameraData = frameData.Get<UniversalCameraData>();
			PassData passData;
			using IRasterRenderGraphBuilder rasterRenderGraphBuilder = renderGraph.AddRasterRenderPass<PassData>(base.passName, out passData, base.profilingSampler, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\MotionVectorRenderPass.cs", 217);
			rasterRenderGraphBuilder.UseAllGlobalTextures(enable: true);
			rasterRenderGraphBuilder.AllowGlobalStateModification(value: true);
			if (universalCameraData.xr.enabled)
			{
				rasterRenderGraphBuilder.EnableFoveatedRasterization(universalCameraData.xr.supportsFoveatedRendering && universalCameraData.xrUniversal.canFoveateIntermediatePasses);
				rasterRenderGraphBuilder.SetExtendedFeatureFlags(ExtendedFeatureFlags.MultiviewRenderRegionsCompatible);
			}
			rasterRenderGraphBuilder.SetRenderAttachment(motionVectorColor, 0);
			rasterRenderGraphBuilder.SetRenderAttachmentDepth(motionVectorDepth);
			InitPassData(ref passData, universalCameraData);
			passData.cameraDepth = cameraDepthTexture;
			rasterRenderGraphBuilder.UseTexture(in cameraDepthTexture);
			InitRendererLists(ref passData, ref universalRenderingData.cullResults, universalRenderingData.supportsDynamicBatching, default(ScriptableRenderContext), renderGraph, useRenderGraph: true);
			rasterRenderGraphBuilder.UseRendererList(in passData.rendererListHdl);
			if (motionVectorColor.IsValid())
			{
				rasterRenderGraphBuilder.SetGlobalTextureAfterPass(in motionVectorColor, Shader.PropertyToID("_MotionVectorTexture"));
			}
			if (motionVectorDepth.IsValid())
			{
				rasterRenderGraphBuilder.SetGlobalTextureAfterPass(in motionVectorDepth, Shader.PropertyToID("_MotionVectorDepthTexture"));
			}
			rasterRenderGraphBuilder.SetRenderFunc(delegate(PassData data, RasterGraphContext context)
			{
				if (data.cameraMaterial != null)
				{
					data.cameraMaterial.SetTexture(s_CameraDepthTextureID, data.cameraDepth);
				}
				ExecutePass(context.cmd, data, data.rendererListHdl);
			});
		}

		internal static void SetRenderGraphMotionVectorGlobalMatrices(RenderGraph renderGraph, UniversalCameraData cameraData)
		{
			if (!cameraData.camera.TryGetComponent<UniversalAdditionalCameraData>(out var component))
			{
				return;
			}
			MotionMatrixPassData passData;
			using IRasterRenderGraphBuilder rasterRenderGraphBuilder = renderGraph.AddRasterRenderPass<MotionMatrixPassData>(s_SetMotionMatrixProfilingSampler.name, out passData, s_SetMotionMatrixProfilingSampler, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\Passes\\MotionVectorRenderPass.cs", 275);
			passData.motionData = component.motionVectorsPersistentData;
			passData.xr = cameraData.xr;
			rasterRenderGraphBuilder.AllowGlobalStateModification(value: true);
			rasterRenderGraphBuilder.SetRenderFunc(delegate(MotionMatrixPassData data, RasterGraphContext context)
			{
				data.motionData.SetGlobalMotionMatrices(context.cmd, data.xr);
			});
		}
	}
}
