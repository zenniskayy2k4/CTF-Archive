using UnityEngine.Rendering.RenderGraphModule;
using UnityEngine.Rendering.RenderGraphModule.Util;
using UnityEngine.Scripting.APIUpdating;

namespace UnityEngine.Rendering.Universal
{
	[MovedFrom("")]
	public class FullScreenPassRendererFeature : ScriptableRendererFeature, ISerializationCallbackReceiver
	{
		public enum InjectionPoint
		{
			BeforeRenderingTransparents = 450,
			BeforeRenderingPostProcessing = 550,
			AfterRenderingPostProcessing = 600
		}

		internal class FullScreenRenderPass : ScriptableRenderPass
		{
			private class CopyPassData
			{
				internal TextureHandle inputTexture;
			}

			private class MainPassData
			{
				internal Material material;

				internal int passIndex;

				internal TextureHandle inputTexture;
			}

			private Material m_Material;

			private int m_PassIndex;

			private bool m_FetchActiveColor;

			private bool m_BindDepthStencilAttachment;

			private static MaterialPropertyBlock s_SharedPropertyBlock = new MaterialPropertyBlock();

			public FullScreenRenderPass(string passName)
			{
				base.profilingSampler = new ProfilingSampler(passName);
			}

			public void SetupMembers(Material material, int passIndex, bool fetchActiveColor, bool bindDepthStencilAttachment)
			{
				m_Material = material;
				m_PassIndex = passIndex;
				m_FetchActiveColor = fetchActiveColor;
				m_BindDepthStencilAttachment = bindDepthStencilAttachment;
			}

			internal void ReAllocate(RenderTextureDescriptor desc)
			{
			}

			private static void ExecuteCopyColorPass(RasterCommandBuffer cmd, RTHandle sourceTexture)
			{
				Blitter.BlitTexture(cmd, sourceTexture, new Vector4(1f, 1f, 0f, 0f), 0f, bilinear: false);
			}

			private static void ExecuteMainPass(RasterCommandBuffer cmd, RTHandle sourceTexture, Material material, int passIndex)
			{
				s_SharedPropertyBlock.Clear();
				if (sourceTexture != null)
				{
					s_SharedPropertyBlock.SetTexture(ShaderPropertyId.blitTexture, sourceTexture);
				}
				s_SharedPropertyBlock.SetVector(ShaderPropertyId.blitScaleBias, new Vector4(1f, 1f, 0f, 0f));
				cmd.DrawProcedural(Matrix4x4.identity, material, passIndex, MeshTopology.Triangles, 3, 1, s_SharedPropertyBlock);
			}

			public override void RecordRenderGraph(RenderGraph renderGraph, ContextContainer frameData)
			{
				UniversalResourceData universalResourceData = frameData.Get<UniversalResourceData>();
				UniversalCameraData cameraData = frameData.Get<UniversalCameraData>();
				TextureHandle activeColorTexture;
				TextureHandle textureHandle;
				if (m_FetchActiveColor)
				{
					TextureDesc desc = renderGraph.GetTextureDesc(universalResourceData.cameraColor);
					desc.name = "_CameraColorFullScreenPass";
					desc.clearBuffer = false;
					activeColorTexture = universalResourceData.activeColorTexture;
					textureHandle = renderGraph.CreateTexture(in desc);
					renderGraph.AddBlitPass(activeColorTexture, textureHandle, Vector2.one, Vector2.zero, 0, 0, -1, 0, 0, 1, UnityEngine.Rendering.RenderGraphModule.Util.RenderGraphUtils.BlitFilterMode.ClampBilinear, "Copy Color Full Screen", returnBuilder: false, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\RendererFeatures\\FullScreenPassRendererFeature.cs", 238);
					activeColorTexture = textureHandle;
				}
				else
				{
					activeColorTexture = TextureHandle.nullHandle;
				}
				textureHandle = universalResourceData.activeColorTexture;
				if (base.input != ScriptableRenderPassInput.None || m_BindDepthStencilAttachment)
				{
					AddFullscreenRenderPassInputPass(renderGraph, universalResourceData, cameraData, activeColorTexture, textureHandle);
					return;
				}
				UnityEngine.Rendering.RenderGraphModule.Util.RenderGraphUtils.BlitMaterialParameters blitParameters = new UnityEngine.Rendering.RenderGraphModule.Util.RenderGraphUtils.BlitMaterialParameters(activeColorTexture, textureHandle, m_Material, m_PassIndex);
				renderGraph.AddBlitPass(blitParameters, "Blit Color Full Screen", returnBuilder: false, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\RendererFeatures\\FullScreenPassRendererFeature.cs", 261);
			}

			private void AddFullscreenRenderPassInputPass(RenderGraph renderGraph, UniversalResourceData resourcesData, UniversalCameraData cameraData, TextureHandle source, TextureHandle destination)
			{
				MainPassData passData;
				using IRasterRenderGraphBuilder rasterRenderGraphBuilder = renderGraph.AddRasterRenderPass<MainPassData>(base.passName, out passData, base.profilingSampler, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\RendererFeatures\\FullScreenPassRendererFeature.cs", 267);
				passData.material = m_Material;
				passData.passIndex = m_PassIndex;
				passData.inputTexture = source;
				if (passData.inputTexture.IsValid())
				{
					rasterRenderGraphBuilder.UseTexture(in passData.inputTexture);
				}
				bool num = (base.input & ScriptableRenderPassInput.Color) != 0;
				bool flag = (base.input & ScriptableRenderPassInput.Depth) != 0;
				bool flag2 = (base.input & ScriptableRenderPassInput.Motion) != 0;
				bool flag3 = (base.input & ScriptableRenderPassInput.Normal) != 0;
				if (num && cameraData.renderer.SupportsCameraOpaque())
				{
					rasterRenderGraphBuilder.UseTexture(resourcesData.cameraOpaqueTexture);
				}
				if (flag)
				{
					rasterRenderGraphBuilder.UseTexture(resourcesData.cameraDepthTexture);
				}
				if (flag2 && cameraData.renderer.SupportsMotionVectors())
				{
					rasterRenderGraphBuilder.UseTexture(resourcesData.motionVectorColor);
					rasterRenderGraphBuilder.UseTexture(resourcesData.motionVectorDepth);
				}
				if (flag3 && cameraData.renderer.SupportsCameraNormals())
				{
					rasterRenderGraphBuilder.UseTexture(resourcesData.cameraNormalsTexture);
				}
				rasterRenderGraphBuilder.SetRenderAttachment(destination, 0);
				if (m_BindDepthStencilAttachment)
				{
					rasterRenderGraphBuilder.SetRenderAttachmentDepth(resourcesData.activeDepthTexture);
				}
				rasterRenderGraphBuilder.SetRenderFunc(delegate(MainPassData data, RasterGraphContext rgContext)
				{
					ExecuteMainPass(rgContext.cmd, data.inputTexture, data.material, data.passIndex);
				});
			}

			private void AddCopyPassRenderPassFullscreen(RenderGraph renderGraph, TextureHandle source, TextureHandle destination)
			{
				CopyPassData passData;
				using IRasterRenderGraphBuilder rasterRenderGraphBuilder = renderGraph.AddRasterRenderPass<CopyPassData>("Copy Color Full Screen", out passData, base.profilingSampler, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\RendererFeatures\\FullScreenPassRendererFeature.cs", 327);
				passData.inputTexture = source;
				rasterRenderGraphBuilder.UseTexture(in passData.inputTexture);
				rasterRenderGraphBuilder.SetRenderAttachment(destination, 0);
				rasterRenderGraphBuilder.SetRenderFunc(delegate(CopyPassData data, RasterGraphContext rgContext)
				{
					ExecuteCopyColorPass(rgContext.cmd, data.inputTexture);
				});
			}
		}

		private enum Version
		{
			Uninitialised = -1,
			Initial = 0,
			AddFetchColorBufferCheckbox = 1,
			Count = 2,
			Latest = 1
		}

		public InjectionPoint injectionPoint = InjectionPoint.AfterRenderingPostProcessing;

		public bool fetchColorBuffer = true;

		public ScriptableRenderPassInput requirements;

		public Material passMaterial;

		public int passIndex;

		public bool bindDepthStencilAttachment;

		private FullScreenRenderPass m_FullScreenPass;

		[SerializeField]
		[HideInInspector]
		private Version m_Version = Version.Uninitialised;

		public override void Create()
		{
			m_FullScreenPass = new FullScreenRenderPass(base.name);
		}

		internal override bool RequireRenderingLayers(bool isDeferred, bool needsGBufferAccurateNormals, out RenderingLayerUtils.Event atEvent, out RenderingLayerUtils.MaskSize maskSize)
		{
			atEvent = RenderingLayerUtils.Event.Opaque;
			maskSize = RenderingLayerUtils.MaskSize.Bits8;
			return false;
		}

		public override void AddRenderPasses(ScriptableRenderer renderer, ref RenderingData renderingData)
		{
			if (renderingData.cameraData.cameraType != CameraType.Preview && renderingData.cameraData.cameraType != CameraType.Reflection && !UniversalRenderer.IsOffscreenDepthTexture(ref renderingData.cameraData) && !(passMaterial == null))
			{
				if (passIndex < 0 || passIndex >= passMaterial.passCount)
				{
					Debug.LogWarningFormat("The full screen feature \"{0}\" will not execute - the pass index is out of bounds for the material.", base.name);
					return;
				}
				m_FullScreenPass.renderPassEvent = (RenderPassEvent)injectionPoint;
				m_FullScreenPass.ConfigureInput(requirements);
				m_FullScreenPass.SetupMembers(passMaterial, passIndex, fetchColorBuffer, bindDepthStencilAttachment);
				m_FullScreenPass.requiresIntermediateTexture = fetchColorBuffer;
				renderer.EnqueuePass(m_FullScreenPass);
			}
		}

		private void UpgradeIfNeeded()
		{
		}

		void ISerializationCallbackReceiver.OnBeforeSerialize()
		{
			if (m_Version == Version.Uninitialised)
			{
				m_Version = Version.AddFetchColorBufferCheckbox;
			}
		}

		void ISerializationCallbackReceiver.OnAfterDeserialize()
		{
			if (m_Version == Version.Uninitialised)
			{
				m_Version = Version.Initial;
			}
			UpgradeIfNeeded();
		}
	}
}
