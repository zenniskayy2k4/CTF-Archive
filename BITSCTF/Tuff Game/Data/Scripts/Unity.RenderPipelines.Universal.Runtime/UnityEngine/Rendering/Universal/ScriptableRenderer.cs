using System;
using System.Collections.Generic;
using System.ComponentModel;
using Unity.Collections;
using UnityEngine.Experimental.Rendering;
using UnityEngine.Rendering.RenderGraphModule;
using UnityEngine.VFX;

namespace UnityEngine.Rendering.Universal
{
	public abstract class ScriptableRenderer : IDisposable
	{
		private static class Profiling
		{
			private const string k_Name = "ScriptableRenderer";

			public static readonly ProfilingSampler setPerCameraShaderVariables = new ProfilingSampler("ScriptableRenderer.SetPerCameraShaderVariables");

			public static readonly ProfilingSampler sortRenderPasses = new ProfilingSampler("Sort Render Passes");

			public static readonly ProfilingSampler recordRenderGraph = new ProfilingSampler("On Record Render Graph");

			public static readonly ProfilingSampler setupCamera = new ProfilingSampler("Setup Camera Properties");

			public static readonly ProfilingSampler vfxProcessCamera = new ProfilingSampler("VFX Process Camera");

			public static readonly ProfilingSampler addRenderPasses = new ProfilingSampler("ScriptableRenderer.AddRenderPasses");

			public static readonly ProfilingSampler clearRenderingState = new ProfilingSampler("ScriptableRenderer.ClearRenderingState");

			public static readonly ProfilingSampler internalFinishRenderingCommon = new ProfilingSampler("ScriptableRenderer.InternalFinishRenderingCommon");

			public static readonly ProfilingSampler drawGizmos = new ProfilingSampler("DrawGizmos");

			public static readonly ProfilingSampler drawWireOverlay = new ProfilingSampler("DrawWireOverlay");

			internal static readonly ProfilingSampler beginXRRendering = new ProfilingSampler("Begin XR Rendering");

			internal static readonly ProfilingSampler endXRRendering = new ProfilingSampler("End XR Rendering");

			internal static readonly ProfilingSampler initRenderGraphFrame = new ProfilingSampler("Initialize Frame");

			internal static readonly ProfilingSampler setEditorTarget = new ProfilingSampler("Set Editor Target");
		}

		public class RenderingFeatures
		{
			[Obsolete("cameraStacking has been deprecated use SupportedCameraRenderTypes() in ScriptableRenderer instead. #from(2022.2) #breakingFrom(2023.1)", true)]
			public bool cameraStacking { get; set; }

			public bool msaa { get; set; } = true;
		}

		private static class RenderPassBlock
		{
			public static readonly int BeforeRendering = 0;

			public static readonly int MainRenderingOpaque = 1;

			public static readonly int MainRenderingTransparent = 2;

			public static readonly int AfterRendering = 3;
		}

		private class VFXProcessCameraPassData
		{
			internal UniversalRenderingData renderingData;

			internal Camera camera;

			internal VFXCameraXRSettings cameraXRSettings;

			internal XRPass xrPass;
		}

		private class DrawGizmosPassData
		{
			public RendererListHandle gizmoRenderList;

			public TextureHandle color;

			public TextureHandle depth;
		}

		private class DrawWireOverlayPassData
		{
			public RendererListHandle wireOverlayList;
		}

		private class BeginXRPassData
		{
			internal UniversalCameraData cameraData;
		}

		private class EndXRPassData
		{
			public UniversalCameraData cameraData;
		}

		private class DummyData
		{
		}

		private class PassData
		{
			internal ScriptableRenderer renderer;

			internal UniversalCameraData cameraData;

			internal TextureHandle target;

			internal Vector2Int cameraTargetSizeCopy;
		}

		internal struct RenderBlocks : IDisposable
		{
			public struct BlockRange : IDisposable
			{
				private int m_Current;

				private int m_End;

				public int Current => m_Current;

				public BlockRange(int begin, int end)
				{
					m_Current = ((begin < end) ? begin : end);
					m_End = ((end >= begin) ? end : begin);
					m_Current--;
				}

				public BlockRange GetEnumerator()
				{
					return this;
				}

				public bool MoveNext()
				{
					return ++m_Current < m_End;
				}

				public void Dispose()
				{
				}
			}

			private NativeArray<RenderPassEvent> m_BlockEventLimits;

			private NativeArray<int> m_BlockRanges;

			private NativeArray<int> m_BlockRangeLengths;

			public RenderBlocks(List<ScriptableRenderPass> activeRenderPassQueue)
			{
				m_BlockEventLimits = new NativeArray<RenderPassEvent>(4, Allocator.Temp);
				m_BlockRanges = new NativeArray<int>(m_BlockEventLimits.Length + 1, Allocator.Temp);
				m_BlockRangeLengths = new NativeArray<int>(m_BlockRanges.Length, Allocator.Temp);
				m_BlockEventLimits[RenderPassBlock.BeforeRendering] = RenderPassEvent.BeforeRenderingPrePasses;
				m_BlockEventLimits[RenderPassBlock.MainRenderingOpaque] = RenderPassEvent.AfterRenderingOpaques;
				m_BlockEventLimits[RenderPassBlock.MainRenderingTransparent] = RenderPassEvent.AfterRenderingPostProcessing;
				m_BlockEventLimits[RenderPassBlock.AfterRendering] = (RenderPassEvent)2147483647;
				FillBlockRanges(activeRenderPassQueue);
				m_BlockEventLimits.Dispose();
				for (int i = 0; i < m_BlockRanges.Length - 1; i++)
				{
					m_BlockRangeLengths[i] = m_BlockRanges[i + 1] - m_BlockRanges[i];
				}
			}

			public void Dispose()
			{
				m_BlockRangeLengths.Dispose();
				m_BlockRanges.Dispose();
			}

			private void FillBlockRanges(List<ScriptableRenderPass> activeRenderPassQueue)
			{
				int index = 0;
				int i = 0;
				m_BlockRanges[index++] = 0;
				for (int j = 0; j < m_BlockEventLimits.Length - 1; j++)
				{
					for (; i < activeRenderPassQueue.Count && activeRenderPassQueue[i].renderPassEvent < m_BlockEventLimits[j]; i++)
					{
					}
					m_BlockRanges[index++] = i;
				}
				m_BlockRanges[index] = activeRenderPassQueue.Count;
			}

			public int GetLength(int index)
			{
				return m_BlockRangeLengths[index];
			}

			public BlockRange GetRange(int index)
			{
				return new BlockRange(m_BlockRanges[index], m_BlockRanges[index + 1]);
			}
		}

		internal bool hasReleasedRTs = true;

		internal static ScriptableRenderer current = null;

		private StoreActionsOptimization m_StoreActionsOptimizationSetting;

		private static bool m_UseOptimizedStoreActions = false;

		private const int k_RenderPassBlockCount = 4;

		protected static readonly RTHandle k_CameraTarget = RTHandles.Alloc(BuiltinRenderTextureType.CameraTarget);

		private List<ScriptableRenderPass> m_ActiveRenderPassQueue = new List<ScriptableRenderPass>(32);

		private List<ScriptableRendererFeature> m_RendererFeatures = new List<ScriptableRendererFeature>(10);

		private RTHandle m_CameraColorTarget;

		private RTHandle m_CameraDepthTarget;

		private RTHandle m_CameraResolveTarget;

		private bool m_FirstTimeCameraColorTargetIsBound = true;

		private bool m_FirstTimeCameraDepthTargetIsBound = true;

		private bool m_IsPipelineExecuting;

		internal bool useRenderPassEnabled;

		private static RenderTargetIdentifier[] m_ActiveColorAttachmentIDs = new RenderTargetIdentifier[8];

		private static RTHandle[] m_ActiveColorAttachments = new RTHandle[8];

		private static RTHandle m_ActiveDepthAttachment;

		private ContextContainer m_frameData = new ContextContainer();

		private static RenderBufferStoreAction[] m_ActiveColorStoreActions = new RenderBufferStoreAction[8];

		private static RenderBufferStoreAction m_ActiveDepthStoreAction = RenderBufferStoreAction.Store;

		private static RenderTargetIdentifier[][] m_TrimmedColorAttachmentCopyIDs = new RenderTargetIdentifier[9][]
		{
			Array.Empty<RenderTargetIdentifier>(),
			new RenderTargetIdentifier[1],
			new RenderTargetIdentifier[2],
			new RenderTargetIdentifier[3],
			new RenderTargetIdentifier[4],
			new RenderTargetIdentifier[5],
			new RenderTargetIdentifier[6],
			new RenderTargetIdentifier[7],
			new RenderTargetIdentifier[8]
		};

		private static RTHandle[][] m_TrimmedColorAttachmentCopies = new RTHandle[9][]
		{
			Array.Empty<RTHandle>(),
			new RTHandle[1],
			new RTHandle[2],
			new RTHandle[3],
			new RTHandle[4],
			new RTHandle[5],
			new RTHandle[6],
			new RTHandle[7],
			new RTHandle[8]
		};

		private static Plane[] s_Planes = new Plane[6];

		private static Vector4[] s_VectorPlanes = new Vector4[6];

		[Obsolete("cameraDepth has been renamed to cameraDepthTarget. #from(2021.1) #breakingFrom(2023.1) (UnityUpgradable) -> cameraDepthTarget", true)]
		[EditorBrowsable(EditorBrowsableState.Never)]
		public RenderTargetIdentifier cameraDepth => m_CameraDepthTarget.nameID;

		[Obsolete("This rendering path is for Compatibility Mode only which has been deprecated and hidden behind URP_COMPATIBILITY_MODE define. This will do nothing.")]
		protected ProfilingSampler profilingExecute { get; set; }

		[Obsolete("This rendering path is for Compatibility Mode only which has been deprecated and hidden behind URP_COMPATIBILITY_MODE define. This will do nothing.")]
		public RTHandle cameraColorTargetHandle
		{
			get
			{
				return null;
			}
			set
			{
			}
		}

		[Obsolete("This rendering path is for Compatibility Mode only which has been deprecated and hidden behind URP_COMPATIBILITY_MODE define. This will do nothing.")]
		public RTHandle cameraDepthTargetHandle
		{
			get
			{
				return null;
			}
			set
			{
			}
		}

		internal DebugHandler DebugHandler { get; }

		[Obsolete("Use cameraColorTargetHandle. #from(2022.1) #breakingFrom(2023.2)", true)]
		public RenderTargetIdentifier cameraColorTarget
		{
			get
			{
				throw new NotSupportedException("cameraColorTarget has been deprecated. Use cameraColorTargetHandle instead");
			}
		}

		protected List<ScriptableRendererFeature> rendererFeatures => m_RendererFeatures;

		protected List<ScriptableRenderPass> activeRenderPassQueue => m_ActiveRenderPassQueue;

		public RenderingFeatures supportedRenderingFeatures { get; set; } = new RenderingFeatures();

		public GraphicsDeviceType[] unsupportedGraphicsDeviceTypes { get; set; } = new GraphicsDeviceType[0];

		internal ContextContainer frameData => m_frameData;

		internal bool useDepthPriming { get; set; }

		internal bool stripShadowsOffVariants { get; set; }

		internal bool stripAdditionalLightOffVariants { get; set; }

		internal virtual bool supportsNativeRenderPassRendergraphCompiler => false;

		public virtual bool supportsGPUOcclusion => false;

		[Obsolete("This rendering path is for Compatibility Mode only which has been deprecated and hidden behind URP_COMPATIBILITY_MODE define. This will do nothing.")]
		public static void SetCameraMatrices(CommandBuffer cmd, ref CameraData cameraData, bool setInverseMatrices)
		{
		}

		[Obsolete("This rendering path is for Compatibility Mode only which has been deprecated and hidden behind URP_COMPATIBILITY_MODE define. This will do nothing.")]
		public static void SetCameraMatrices(CommandBuffer cmd, UniversalCameraData cameraData, bool setInverseMatrices)
		{
		}

		[Obsolete("This rendering path is for Compatibility Mode only which has been deprecated and hidden behind URP_COMPATIBILITY_MODE define. This will do nothing.")]
		public void ConfigureCameraTarget(RTHandle colorTarget, RTHandle depthTarget)
		{
		}

		[Obsolete("This rendering path is for Compatibility Mode only which has been deprecated and hidden behind URP_COMPATIBILITY_MODE define. This will do nothing.")]
		public virtual void Setup(ScriptableRenderContext context, ref RenderingData renderingData)
		{
		}

		[Obsolete("This rendering path is for Compatibility Mode only which has been deprecated and hidden behind URP_COMPATIBILITY_MODE define. This will do nothing.")]
		public virtual void SetupLights(ScriptableRenderContext context, ref RenderingData renderingData)
		{
		}

		[Obsolete("This rendering path is for Compatibility Mode only which has been deprecated and hidden behind URP_COMPATIBILITY_MODE define. This will do nothing.")]
		public void Execute(ScriptableRenderContext context, ref RenderingData renderingData)
		{
		}

		[Obsolete("This rendering path is for Compatibility Mode only which has been deprecated and hidden behind URP_COMPATIBILITY_MODE define. This will do nothing.")]
		protected void SetupRenderPasses(in RenderingData renderingData)
		{
		}

		public virtual int SupportedCameraStackingTypes()
		{
			return 0;
		}

		public bool SupportsCameraStackingType(CameraRenderType cameraRenderType)
		{
			return (SupportedCameraStackingTypes() & (1 << (int)cameraRenderType)) != 0;
		}

		protected internal virtual bool SupportsMotionVectors()
		{
			return false;
		}

		protected internal virtual bool SupportsCameraOpaque()
		{
			return false;
		}

		protected internal virtual bool SupportsCameraNormals()
		{
			return false;
		}

		internal static void SetCameraMatrices(RasterCommandBuffer cmd, UniversalCameraData cameraData, bool setInverseMatrices, bool isTargetFlipped)
		{
			if (cameraData.xr.enabled)
			{
				cameraData.PushBuiltinShaderConstantsXR(cmd, isTargetFlipped);
				XRSystemUniversal.MarkShaderProperties(cmd, cameraData.xrUniversal, isTargetFlipped);
				return;
			}
			Matrix4x4 viewMatrix = cameraData.GetViewMatrix();
			Matrix4x4 projectionMatrix = cameraData.GetProjectionMatrix();
			cmd.SetViewProjectionMatrices(viewMatrix, projectionMatrix);
			if (setInverseMatrices)
			{
				Matrix4x4 gPUProjectionMatrix = cameraData.GetGPUProjectionMatrix(isTargetFlipped);
				Matrix4x4 matrix4x = Matrix4x4.Inverse(viewMatrix);
				Matrix4x4 matrix4x2 = Matrix4x4.Inverse(gPUProjectionMatrix);
				Matrix4x4 value = matrix4x * matrix4x2;
				Matrix4x4 value2 = Matrix4x4.Scale(new Vector3(1f, 1f, -1f)) * viewMatrix;
				Matrix4x4 inverse = value2.inverse;
				cmd.SetGlobalMatrix(ShaderPropertyId.worldToCameraMatrix, value2);
				cmd.SetGlobalMatrix(ShaderPropertyId.cameraToWorldMatrix, inverse);
				cmd.SetGlobalMatrix(ShaderPropertyId.inverseViewMatrix, matrix4x);
				cmd.SetGlobalMatrix(ShaderPropertyId.inverseProjectionMatrix, matrix4x2);
				cmd.SetGlobalMatrix(ShaderPropertyId.inverseViewAndProjectionMatrix, value);
			}
		}

		private void SetPerCameraShaderVariables(RasterCommandBuffer cmd, UniversalCameraData cameraData, Vector2Int cameraTargetSizeCopy, bool isTargetFlipped)
		{
			using (new ProfilingScope(Profiling.setPerCameraShaderVariables))
			{
				Camera camera = cameraData.camera;
				float num = cameraTargetSizeCopy.x;
				float num2 = cameraTargetSizeCopy.y;
				float num3 = camera.pixelWidth;
				float num4 = camera.pixelHeight;
				if (cameraData.renderType == CameraRenderType.Overlay)
				{
					num3 = cameraData.pixelWidth;
					num4 = cameraData.pixelHeight;
				}
				if (cameraData.xr.enabled)
				{
					num3 = cameraTargetSizeCopy.x;
					num4 = cameraTargetSizeCopy.y;
					useRenderPassEnabled = false;
				}
				if (camera.allowDynamicResolution)
				{
					num *= ScalableBufferManager.widthScaleFactor;
					num2 *= ScalableBufferManager.heightScaleFactor;
				}
				float nearClipPlane = camera.nearClipPlane;
				float farClipPlane = camera.farClipPlane;
				float num5 = (Mathf.Approximately(nearClipPlane, 0f) ? 0f : (1f / nearClipPlane));
				float num6 = (Mathf.Approximately(farClipPlane, 0f) ? 0f : (1f / farClipPlane));
				float w = (camera.orthographic ? 1f : 0f);
				float num7 = 1f - farClipPlane * num5;
				float num8 = farClipPlane * num5;
				Vector4 value = new Vector4(num7, num8, num7 * num6, num8 * num6);
				if (SystemInfo.usesReversedZBuffer)
				{
					value.y += value.x;
					value.x = 0f - value.x;
					value.w += value.z;
					value.z = 0f - value.z;
				}
				if (cameraData.renderType == CameraRenderType.Overlay)
				{
					float x = (isTargetFlipped ? (-1f) : 1f);
					cmd.SetGlobalVector(value: new Vector4(x, nearClipPlane, farClipPlane, 1f * num6), nameID: ShaderPropertyId.projectionParams);
				}
				Vector4 value2 = new Vector4(camera.orthographicSize * cameraData.aspectRatio, camera.orthographicSize, 0f, w);
				cmd.SetGlobalVector(ShaderPropertyId.worldSpaceCameraPos, cameraData.worldSpaceCameraPos);
				cmd.SetGlobalVector(ShaderPropertyId.screenParams, new Vector4(num3, num4, 1f + 1f / num3, 1f + 1f / num4));
				cmd.SetGlobalVector(ShaderPropertyId.scaledScreenParams, new Vector4(num, num2, 1f + 1f / num, 1f + 1f / num2));
				cmd.SetGlobalVector(ShaderPropertyId.zBufferParams, value);
				cmd.SetGlobalVector(ShaderPropertyId.orthoParams, value2);
				cmd.SetGlobalVector(ShaderPropertyId.screenSize, new Vector4(num, num2, 1f / num, 1f / num2));
				cmd.SetKeyword(in ShaderGlobalKeywords.SCREEN_COORD_OVERRIDE, cameraData.useScreenCoordOverride);
				cmd.SetGlobalVector(ShaderPropertyId.screenSizeOverride, cameraData.screenSizeOverride);
				cmd.SetGlobalVector(ShaderPropertyId.screenCoordScaleBias, cameraData.screenCoordScaleBias);
				cmd.SetGlobalVector(ShaderPropertyId.rtHandleScale, Vector4.one);
				float val = Math.Min((float)(0.0 - Math.Log(num3 / num, 2.0)), 0f);
				float val2 = Math.Min(cameraData.taaSettings.mipBias, 0f);
				val = Math.Min(val, val2);
				cmd.SetGlobalVector(ShaderPropertyId.globalMipBias, new Vector2(val, Mathf.Pow(2f, val)));
				SetCameraMatrices(cmd, cameraData, setInverseMatrices: true, isTargetFlipped);
			}
		}

		private void SetPerCameraBillboardProperties(RasterCommandBuffer cmd, UniversalCameraData cameraData)
		{
			Matrix4x4 worldToCameraMatrix = cameraData.GetViewMatrix();
			Vector3 worldSpaceCameraPos = cameraData.worldSpaceCameraPos;
			cmd.SetKeyword(in ShaderGlobalKeywords.BillboardFaceCameraPos, QualitySettings.billboardsFaceCameraPosition);
			CalculateBillboardProperties(in worldToCameraMatrix, out var billboardTangent, out var billboardNormal, out var cameraXZAngle);
			cmd.SetGlobalVector(ShaderPropertyId.billboardNormal, new Vector4(billboardNormal.x, billboardNormal.y, billboardNormal.z, 0f));
			cmd.SetGlobalVector(ShaderPropertyId.billboardTangent, new Vector4(billboardTangent.x, billboardTangent.y, billboardTangent.z, 0f));
			cmd.SetGlobalVector(ShaderPropertyId.billboardCameraParams, new Vector4(worldSpaceCameraPos.x, worldSpaceCameraPos.y, worldSpaceCameraPos.z, cameraXZAngle));
		}

		private static void CalculateBillboardProperties(in Matrix4x4 worldToCameraMatrix, out Vector3 billboardTangent, out Vector3 billboardNormal, out float cameraXZAngle)
		{
			Matrix4x4 matrix4x = worldToCameraMatrix;
			matrix4x = matrix4x.transpose;
			Vector3 vector = new Vector3(matrix4x.m00, matrix4x.m10, matrix4x.m20);
			Vector3 vector2 = new Vector3(matrix4x.m01, matrix4x.m11, matrix4x.m21);
			Vector3 lhs = new Vector3(matrix4x.m02, matrix4x.m12, matrix4x.m22);
			Vector3 up = Vector3.up;
			Vector3 vector3 = Vector3.Cross(lhs, up);
			billboardTangent = ((!Mathf.Approximately(vector3.sqrMagnitude, 0f)) ? vector3.normalized : vector);
			billboardNormal = Vector3.Cross(up, billboardTangent);
			billboardNormal = ((!Mathf.Approximately(billboardNormal.sqrMagnitude, 0f)) ? billboardNormal.normalized : vector2);
			Vector3 vector4 = new Vector3(0f, 0f, 1f);
			float y = vector4.x * billboardTangent.z - vector4.z * billboardTangent.x;
			float x = vector4.x * billboardTangent.x + vector4.z * billboardTangent.z;
			cameraXZAngle = Mathf.Atan2(y, x);
			if (cameraXZAngle < 0f)
			{
				cameraXZAngle += MathF.PI * 2f;
			}
		}

		private void SetPerCameraClippingPlaneProperties(RasterCommandBuffer cmd, in UniversalCameraData cameraData, bool isTargetFlipped)
		{
			Matrix4x4 gPUProjectionMatrix = cameraData.GetGPUProjectionMatrix(isTargetFlipped);
			Matrix4x4 viewMatrix = cameraData.GetViewMatrix();
			Matrix4x4 worldToProjectionMatrix = CoreMatrixUtils.MultiplyProjectionMatrix(gPUProjectionMatrix, viewMatrix, cameraData.camera.orthographic);
			Plane[] array = s_Planes;
			GeometryUtility.CalculateFrustumPlanes(worldToProjectionMatrix, array);
			Vector4[] array2 = s_VectorPlanes;
			for (int i = 0; i < array.Length; i++)
			{
				array2[i] = new Vector4(array[i].normal.x, array[i].normal.y, array[i].normal.z, array[i].distance);
			}
			cmd.SetGlobalVectorArray(ShaderPropertyId.cameraWorldClipPlanes, array2);
		}

		private static void SetShaderTimeValues(IBaseCommandBuffer cmd, float time, float deltaTime, float smoothDeltaTime)
		{
			float f = time / 8f;
			float f2 = time / 4f;
			float f3 = time / 2f;
			float num = time - ShaderUtils.PersistentDeltaTime;
			Vector4 value = time * new Vector4(0.05f, 1f, 2f, 3f);
			Vector4 value2 = new Vector4(Mathf.Sin(f), Mathf.Sin(f2), Mathf.Sin(f3), Mathf.Sin(time));
			Vector4 value3 = new Vector4(Mathf.Cos(f), Mathf.Cos(f2), Mathf.Cos(f3), Mathf.Cos(time));
			Vector4 value4 = new Vector4(deltaTime, 1f / deltaTime, smoothDeltaTime, 1f / smoothDeltaTime);
			Vector4 value5 = new Vector4(time, Mathf.Sin(time), Mathf.Cos(time), 0f);
			Vector4 value6 = new Vector4(num, Mathf.Sin(num), Mathf.Cos(num), 0f);
			cmd.SetGlobalVector(ShaderPropertyId.time, value);
			cmd.SetGlobalVector(ShaderPropertyId.sinTime, value2);
			cmd.SetGlobalVector(ShaderPropertyId.cosTime, value3);
			cmd.SetGlobalVector(ShaderPropertyId.deltaTime, value4);
			cmd.SetGlobalVector(ShaderPropertyId.timeParameters, value5);
			cmd.SetGlobalVector(ShaderPropertyId.lastTimeParameters, value6);
		}

		public ScriptableRenderer(ScriptableRendererData data)
		{
			foreach (ScriptableRendererFeature rendererFeature in data.rendererFeatures)
			{
				if (!(rendererFeature == null))
				{
					rendererFeature.Create();
					m_RendererFeatures.Add(rendererFeature);
				}
			}
			useRenderPassEnabled = data.useNativeRenderPass;
			Clear(CameraRenderType.Base);
			m_ActiveRenderPassQueue.Clear();
			if ((bool)UniversalRenderPipeline.asset)
			{
				m_StoreActionsOptimizationSetting = UniversalRenderPipeline.asset.storeActionsOptimization;
			}
			m_UseOptimizedStoreActions = m_StoreActionsOptimizationSetting != StoreActionsOptimization.Store;
		}

		public void Dispose()
		{
			for (int i = 0; i < m_RendererFeatures.Count; i++)
			{
				if (!(rendererFeatures[i] == null))
				{
					try
					{
						rendererFeatures[i].Dispose();
					}
					catch (Exception exception)
					{
						Debug.LogException(exception);
					}
				}
			}
			Dispose(disposing: true);
			hasReleasedRTs = true;
			GC.SuppressFinalize(this);
		}

		protected virtual void Dispose(bool disposing)
		{
			DebugHandler?.Dispose();
		}

		internal virtual void ReleaseRenderTargets()
		{
		}

		public virtual void SetupCullingParameters(ref ScriptableCullingParameters cullingParameters, ref CameraData cameraData)
		{
		}

		public virtual void FinishRendering(CommandBuffer cmd)
		{
		}

		public virtual void OnBeginRenderGraphFrame()
		{
		}

		internal virtual void OnRecordRenderGraph(RenderGraph renderGraph, ScriptableRenderContext context)
		{
		}

		public virtual void OnEndRenderGraphFrame()
		{
		}

		private void InitRenderGraphFrame(RenderGraph renderGraph)
		{
			PassData passData;
			using IUnsafeRenderGraphBuilder unsafeRenderGraphBuilder = renderGraph.AddUnsafePass<PassData>(Profiling.initRenderGraphFrame.name, out passData, Profiling.initRenderGraphFrame, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\ScriptableRenderer.cs", 924);
			passData.renderer = this;
			unsafeRenderGraphBuilder.AllowPassCulling(value: false);
			unsafeRenderGraphBuilder.SetRenderFunc(delegate(PassData data, UnsafeGraphContext rgContext)
			{
				UnsafeCommandBuffer cmd = rgContext.cmd;
				float time = Time.time;
				float deltaTime = Time.deltaTime;
				float smoothDeltaTime = Time.smoothDeltaTime;
				ClearRenderingState(cmd);
				SetShaderTimeValues(cmd, time, deltaTime, smoothDeltaTime);
			});
		}

		internal void ProcessVFXCameraCommand(RenderGraph renderGraph)
		{
			UniversalRenderingData renderingData = frameData.Get<UniversalRenderingData>();
			UniversalCameraData universalCameraData = frameData.Get<UniversalCameraData>();
			XRPass xr = universalCameraData.xr;
			VFXProcessCameraPassData passData;
			using IUnsafeRenderGraphBuilder unsafeRenderGraphBuilder = renderGraph.AddUnsafePass<VFXProcessCameraPassData>("ProcessVFXCameraCommand", out passData, Profiling.vfxProcessCamera, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\ScriptableRenderer.cs", 962);
			passData.camera = universalCameraData.camera;
			passData.renderingData = renderingData;
			passData.cameraXRSettings.viewTotal = ((!xr.enabled) ? 1u : 2u);
			passData.cameraXRSettings.viewCount = ((!xr.enabled) ? 1u : ((uint)xr.viewCount));
			passData.cameraXRSettings.viewOffset = (uint)xr.multipassId;
			passData.xrPass = (xr.enabled ? xr : null);
			unsafeRenderGraphBuilder.AllowPassCulling(value: false);
			unsafeRenderGraphBuilder.SetRenderFunc(delegate(VFXProcessCameraPassData data, UnsafeGraphContext context)
			{
				if (data.xrPass != null)
				{
					data.xrPass.StartSinglePass(context.cmd);
				}
				CommandBufferHelpers.VFXManager_ProcessCameraCommand(data.camera, context.cmd, data.cameraXRSettings, data.renderingData.cullResults);
				if (data.xrPass != null)
				{
					data.xrPass.StopSinglePass(context.cmd);
				}
			});
		}

		internal void SetupRenderGraphCameraProperties(RenderGraph renderGraph, TextureHandle target)
		{
			PassData passData;
			using IRasterRenderGraphBuilder rasterRenderGraphBuilder = renderGraph.AddRasterRenderPass<PassData>(Profiling.setupCamera.name, out passData, Profiling.setupCamera, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\ScriptableRenderer.cs", 992);
			passData.renderer = this;
			passData.cameraData = frameData.Get<UniversalCameraData>();
			passData.cameraTargetSizeCopy = new Vector2Int(passData.cameraData.cameraTargetDescriptor.width, passData.cameraData.cameraTargetDescriptor.height);
			passData.target = target;
			rasterRenderGraphBuilder.AllowGlobalStateModification(value: true);
			rasterRenderGraphBuilder.SetRenderFunc(delegate(PassData data, RasterGraphContext context)
			{
				bool isTargetFlipped = SystemInfo.graphicsUVStartsAtTop && RenderingUtils.IsHandleYFlipped(in context, in data.target);
				if (data.cameraData.renderType == CameraRenderType.Base)
				{
					context.cmd.SetupCameraProperties(data.cameraData.camera);
					data.renderer.SetPerCameraShaderVariables(context.cmd, data.cameraData, data.cameraTargetSizeCopy, isTargetFlipped);
				}
				else
				{
					data.renderer.SetPerCameraShaderVariables(context.cmd, data.cameraData, data.cameraTargetSizeCopy, isTargetFlipped);
					data.renderer.SetPerCameraClippingPlaneProperties(context.cmd, in data.cameraData, isTargetFlipped);
					data.renderer.SetPerCameraBillboardProperties(context.cmd, data.cameraData);
				}
				float time = Time.time;
				float deltaTime = Time.deltaTime;
				float smoothDeltaTime = Time.smoothDeltaTime;
				SetShaderTimeValues(context.cmd, time, deltaTime, smoothDeltaTime);
			});
		}

		internal void DrawRenderGraphGizmos(RenderGraph renderGraph, ContextContainer frameData, TextureHandle color, TextureHandle depth, GizmoSubset gizmoSubset)
		{
		}

		internal void DrawRenderGraphWireOverlay(RenderGraph renderGraph, ContextContainer frameData, TextureHandle color)
		{
		}

		internal void BeginRenderGraphXRRendering(RenderGraph renderGraph)
		{
			UniversalCameraData universalCameraData = frameData.Get<UniversalCameraData>();
			if (!universalCameraData.xr.enabled)
			{
				return;
			}
			bool flag = XRSystem.GetRenderViewportScale() == 1f;
			universalCameraData.xrUniversal.canFoveateIntermediatePasses = !PlatformAutoDetect.isXRMobile || flag;
			BeginXRPassData passData;
			using IRasterRenderGraphBuilder rasterRenderGraphBuilder = renderGraph.AddRasterRenderPass<BeginXRPassData>("BeginXRRendering", out passData, Profiling.beginXRRendering, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\ScriptableRenderer.cs", 1140);
			passData.cameraData = universalCameraData;
			rasterRenderGraphBuilder.AllowGlobalStateModification(value: true);
			rasterRenderGraphBuilder.SetRenderFunc(delegate(BeginXRPassData data, RasterGraphContext context)
			{
				if (data.cameraData.xr.enabled)
				{
					if (data.cameraData.xrUniversal.isLateLatchEnabled)
					{
						data.cameraData.xrUniversal.canMarkLateLatch = true;
					}
					data.cameraData.xr.StartSinglePass(context.cmd);
					if (data.cameraData.xr.supportsFoveatedRendering)
					{
						context.cmd.ConfigureFoveatedRendering(data.cameraData.xr.foveatedRenderingInfo);
						if (XRSystem.foveatedRenderingCaps.HasFlag(FoveatedRenderingCaps.NonUniformRaster))
						{
							context.cmd.SetKeyword(in ShaderGlobalKeywords.FoveatedRenderingNonUniformRaster, value: true);
						}
					}
				}
			});
		}

		internal void EndRenderGraphXRRendering(RenderGraph renderGraph)
		{
			UniversalCameraData universalCameraData = frameData.Get<UniversalCameraData>();
			if (!universalCameraData.xr.enabled)
			{
				return;
			}
			EndXRPassData passData;
			using IRasterRenderGraphBuilder rasterRenderGraphBuilder = renderGraph.AddRasterRenderPass<EndXRPassData>("EndXRRendering", out passData, Profiling.endXRRendering, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\ScriptableRenderer.cs", 1180);
			passData.cameraData = universalCameraData;
			rasterRenderGraphBuilder.AllowGlobalStateModification(value: true);
			rasterRenderGraphBuilder.SetExtendedFeatureFlags(ExtendedFeatureFlags.MultiviewRenderRegionsCompatible);
			rasterRenderGraphBuilder.SetRenderFunc(delegate(EndXRPassData data, RasterGraphContext context)
			{
				if (data.cameraData.xr.enabled)
				{
					data.cameraData.xr.StopSinglePass(context.cmd);
				}
				if (XRSystem.foveatedRenderingCaps != FoveatedRenderingCaps.None)
				{
					if (XRSystem.foveatedRenderingCaps.HasFlag(FoveatedRenderingCaps.NonUniformRaster))
					{
						context.cmd.SetKeyword(in ShaderGlobalKeywords.FoveatedRenderingNonUniformRaster, value: false);
					}
					context.cmd.ConfigureFoveatedRendering(IntPtr.Zero);
				}
			});
		}

		private void SetEditorTarget(RenderGraph renderGraph)
		{
			DummyData passData;
			using IUnsafeRenderGraphBuilder unsafeRenderGraphBuilder = renderGraph.AddUnsafePass<DummyData>("SetEditorTarget", out passData, Profiling.setEditorTarget, ".\\Library\\PackageCache\\com.unity.render-pipelines.universal@d10049dfa479\\Runtime\\ScriptableRenderer.cs", 1213);
			unsafeRenderGraphBuilder.AllowPassCulling(value: false);
			unsafeRenderGraphBuilder.SetRenderFunc(delegate(DummyData data, UnsafeGraphContext context)
			{
				context.cmd.SetRenderTarget(BuiltinRenderTextureType.CameraTarget, RenderBufferLoadAction.Load, RenderBufferStoreAction.Store, RenderBufferLoadAction.Load, RenderBufferStoreAction.DontCare);
			});
		}

		internal void RecordRenderGraph(RenderGraph renderGraph, ScriptableRenderContext context)
		{
			using (new ProfilingScope(ProfilingSampler.Get(URPProfileId.RecordRenderGraph)))
			{
				OnBeginRenderGraphFrame();
				using (new ProfilingScope(Profiling.sortRenderPasses))
				{
					SortStable(m_ActiveRenderPassQueue);
				}
				InitRenderGraphFrame(renderGraph);
				using (new ProfilingScope(Profiling.recordRenderGraph))
				{
					OnRecordRenderGraph(renderGraph, context);
				}
				OnEndRenderGraphFrame();
			}
		}

		internal void FinishRenderGraphRendering(CommandBuffer cmd)
		{
			UniversalCameraData universalCameraData = frameData.Get<UniversalCameraData>();
			OnFinishRenderGraphRendering(cmd);
			InternalFinishRenderingCommon(cmd, universalCameraData.resolveFinalTarget);
		}

		internal virtual void OnFinishRenderGraphRendering(CommandBuffer cmd)
		{
		}

		internal void RecordCustomRenderGraphPassesInEventRange(RenderGraph renderGraph, RenderPassEvent eventStart, RenderPassEvent eventEnd)
		{
			if (eventStart == eventEnd)
			{
				return;
			}
			foreach (ScriptableRenderPass item in m_ActiveRenderPassQueue)
			{
				if (item.renderPassEvent >= eventStart && item.renderPassEvent < eventEnd)
				{
					item.RecordRenderGraph(renderGraph, m_frameData);
				}
			}
		}

		internal void CalculateSplitEventRange(RenderPassEvent startInjectionPoint, RenderPassEvent targetEvent, out RenderPassEvent startEvent, out RenderPassEvent splitEvent, out RenderPassEvent endEvent)
		{
			int renderPassEventRange = ScriptableRenderPass.GetRenderPassEventRange(startInjectionPoint);
			startEvent = startInjectionPoint;
			endEvent = startEvent + renderPassEventRange;
			splitEvent = (RenderPassEvent)Math.Clamp((int)targetEvent, (int)startEvent, (int)endEvent);
		}

		internal void RecordCustomRenderGraphPasses(RenderGraph renderGraph, RenderPassEvent startInjectionPoint, RenderPassEvent endInjectionPoint)
		{
			int renderPassEventRange = ScriptableRenderPass.GetRenderPassEventRange(endInjectionPoint);
			RecordCustomRenderGraphPassesInEventRange(renderGraph, startInjectionPoint, endInjectionPoint + renderPassEventRange);
		}

		internal void RecordCustomRenderGraphPasses(RenderGraph renderGraph, RenderPassEvent injectionPoint)
		{
			RecordCustomRenderGraphPasses(renderGraph, injectionPoint, injectionPoint);
		}

		public void EnqueuePass(ScriptableRenderPass pass)
		{
			m_ActiveRenderPassQueue.Add(pass);
		}

		protected static ClearFlag GetCameraClearFlag(ref CameraData cameraData)
		{
			return GetCameraClearFlag(cameraData.universalCameraData);
		}

		protected static ClearFlag GetCameraClearFlag(UniversalCameraData cameraData)
		{
			CameraClearFlags clearFlags = cameraData.camera.clearFlags;
			if (cameraData.renderType == CameraRenderType.Overlay)
			{
				if (!cameraData.clearDepth)
				{
					return ClearFlag.None;
				}
				return ClearFlag.DepthStencil;
			}
			DebugHandler debugHandler = cameraData.renderer.DebugHandler;
			if (debugHandler != null && debugHandler.IsActiveForCamera(cameraData.isPreviewCamera) && debugHandler.IsScreenClearNeeded)
			{
				return ClearFlag.All;
			}
			if (clearFlags == CameraClearFlags.Skybox && RenderSettings.skybox != null && cameraData.postProcessEnabled && cameraData.xr.enabled)
			{
				return ClearFlag.All;
			}
			if ((clearFlags == CameraClearFlags.Skybox && RenderSettings.skybox != null) || clearFlags == CameraClearFlags.Nothing)
			{
				if (cameraData.cameraTargetDescriptor.msaaSamples > 1)
				{
					cameraData.camera.backgroundColor = Color.black;
					return ClearFlag.All;
				}
				return ClearFlag.DepthStencil;
			}
			return ClearFlag.All;
		}

		internal void OnPreCullRenderPasses(in CameraData cameraData)
		{
			for (int i = 0; i < rendererFeatures.Count; i++)
			{
				if (rendererFeatures[i].isActive)
				{
					rendererFeatures[i].OnCameraPreCull(this, in cameraData);
				}
			}
		}

		internal void AddRenderPasses(ref RenderingData renderingData)
		{
			using (new ProfilingScope(Profiling.addRenderPasses))
			{
				for (int i = 0; i < rendererFeatures.Count; i++)
				{
					if (rendererFeatures[i].isActive)
					{
						rendererFeatures[i].AddRenderPasses(this, ref renderingData);
					}
				}
				int count = activeRenderPassQueue.Count;
				for (int num = count - 1; num >= 0; num--)
				{
					if (activeRenderPassQueue[num] == null)
					{
						activeRenderPassQueue.RemoveAt(num);
					}
				}
				if (count > 0 && m_StoreActionsOptimizationSetting == StoreActionsOptimization.Auto)
				{
					m_UseOptimizedStoreActions = false;
				}
			}
		}

		private static void ClearRenderingState(IBaseCommandBuffer cmd)
		{
			using (new ProfilingScope(Profiling.clearRenderingState))
			{
				cmd.SetKeyword(in ShaderGlobalKeywords.MainLightShadows, value: false);
				cmd.SetKeyword(in ShaderGlobalKeywords.MainLightShadowCascades, value: false);
				cmd.SetKeyword(in ShaderGlobalKeywords.AdditionalLightsVertex, value: false);
				cmd.SetKeyword(in ShaderGlobalKeywords.AdditionalLightsPixel, value: false);
				cmd.SetKeyword(in ShaderGlobalKeywords.ClusterLightLoop, value: false);
				cmd.SetKeyword(in ShaderGlobalKeywords.ForwardPlus, value: false);
				cmd.SetKeyword(in ShaderGlobalKeywords.AdditionalLightShadows, value: false);
				cmd.SetKeyword(in ShaderGlobalKeywords.ReflectionProbeBlending, value: false);
				cmd.SetKeyword(in ShaderGlobalKeywords.ReflectionProbeBoxProjection, value: false);
				cmd.SetKeyword(in ShaderGlobalKeywords.ReflectionProbeAtlas, value: false);
				cmd.SetKeyword(in ShaderGlobalKeywords.SoftShadows, value: false);
				cmd.SetKeyword(in ShaderGlobalKeywords.SoftShadowsLow, value: false);
				cmd.SetKeyword(in ShaderGlobalKeywords.SoftShadowsMedium, value: false);
				cmd.SetKeyword(in ShaderGlobalKeywords.SoftShadowsHigh, value: false);
				cmd.SetKeyword(in ShaderGlobalKeywords.MixedLightingSubtractive, value: false);
				cmd.SetKeyword(in ShaderGlobalKeywords.LightmapShadowMixing, value: false);
				cmd.SetKeyword(in ShaderGlobalKeywords.ShadowsShadowMask, value: false);
				cmd.SetKeyword(in ShaderGlobalKeywords.LinearToSRGBConversion, value: false);
				cmd.SetKeyword(in ShaderGlobalKeywords.LightLayers, value: false);
				cmd.SetGlobalVector(ScreenSpaceAmbientOcclusionPass.s_AmbientOcclusionParamID, Vector4.zero);
			}
		}

		internal void Clear(CameraRenderType cameraType)
		{
			m_ActiveColorAttachments[0] = k_CameraTarget;
			for (int i = 1; i < m_ActiveColorAttachments.Length; i++)
			{
				m_ActiveColorAttachments[i] = null;
			}
			for (int j = 0; j < m_ActiveColorAttachments.Length; j++)
			{
				m_ActiveColorAttachmentIDs[j] = m_ActiveColorAttachments[j]?.nameID ?? ((RenderTargetIdentifier)0);
			}
			m_ActiveDepthAttachment = k_CameraTarget;
			m_FirstTimeCameraColorTargetIsBound = cameraType == CameraRenderType.Base;
			m_FirstTimeCameraDepthTargetIsBound = true;
			m_CameraColorTarget = null;
			m_CameraDepthTarget = null;
		}

		internal bool IsSceneFilteringEnabled(Camera camera)
		{
			return false;
		}

		internal virtual void SwapColorBuffer(CommandBuffer cmd)
		{
		}

		internal virtual void EnableSwapBufferMSAA(bool enable)
		{
		}

		private void InternalFinishRenderingCommon(CommandBuffer cmd, bool resolveFinalTarget)
		{
			using (new ProfilingScope(Profiling.internalFinishRenderingCommon))
			{
				for (int i = 0; i < m_ActiveRenderPassQueue.Count; i++)
				{
					m_ActiveRenderPassQueue[i].FrameCleanup(cmd);
				}
				if (resolveFinalTarget)
				{
					FinishRendering(cmd);
					m_IsPipelineExecuting = false;
				}
				m_ActiveRenderPassQueue.Clear();
			}
		}

		private protected int AdjustAndGetScreenMSAASamples(RenderGraph renderGraph, bool useIntermediateColorTarget)
		{
			if (!SystemInfo.supportsMultisampledBackBuffer)
			{
				return 1;
			}
			if (UniversalRenderPipeline.canOptimizeScreenMSAASamples && useIntermediateColorTarget && renderGraph.nativeRenderPassesEnabled && Screen.msaaSamples > 1)
			{
				Screen.SetMSAASamples(1);
			}
			if (Application.platform != RuntimePlatform.OSXPlayer && Application.platform != RuntimePlatform.IPhonePlayer)
			{
				return Mathf.Max(Screen.msaaSamples, 1);
			}
			return Mathf.Max(UniversalRenderPipeline.startFrameScreenMSAASamples, 1);
		}

		internal static void SortStable(List<ScriptableRenderPass> list)
		{
			for (int i = 1; i < list.Count; i++)
			{
				ScriptableRenderPass scriptableRenderPass = list[i];
				int num = i - 1;
				while (num >= 0 && scriptableRenderPass < list[num])
				{
					list[num + 1] = list[num];
					num--;
				}
				list[num + 1] = scriptableRenderPass;
			}
		}
	}
}
