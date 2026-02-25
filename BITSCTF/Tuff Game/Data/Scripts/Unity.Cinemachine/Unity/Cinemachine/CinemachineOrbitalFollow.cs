using System;
using System.Collections.Generic;
using Unity.Cinemachine.TargetTracking;
using UnityEngine;

namespace Unity.Cinemachine
{
	[AddComponentMenu("Cinemachine/Procedural/Position Control/Cinemachine Orbital Follow")]
	[SaveDuringPlay]
	[DisallowMultipleComponent]
	[CameraPipeline(CinemachineCore.Stage.Body)]
	[RequiredTarget(RequiredTargetAttribute.RequiredTargets.Tracking)]
	[HelpURL("https://docs.unity3d.com/Packages/com.unity.cinemachine@3.1/manual/CinemachineOrbitalFollow.html")]
	public class CinemachineOrbitalFollow : CinemachineComponentBase, IInputAxisOwner, IInputAxisResetSource, CinemachineFreeLookModifier.IModifierValueSource, CinemachineFreeLookModifier.IModifiablePositionDamping, CinemachineFreeLookModifier.IModifiableDistance
	{
		public enum OrbitStyles
		{
			Sphere = 0,
			ThreeRing = 1
		}

		public enum ReferenceFrames
		{
			AxisCenter = 0,
			ParentObject = 1,
			TrackingTarget = 2,
			LookAtTarget = 3
		}

		[Tooltip("Offset from the target object's origin in target-local space. Use this to fine-tune the orbit when the desired focus of the orbit is not the tracked object's origin.")]
		public Vector3 TargetOffset;

		public TrackerSettings TrackerSettings = TrackerSettings.Default;

		[Tooltip("Defines the manner in which the orbit surface is constructed.")]
		public OrbitStyles OrbitStyle;

		[Tooltip("The camera will be placed at this distance from the Follow target.")]
		public float Radius = 10f;

		[Tooltip("Defines a complex surface rig from 3 horizontal rings.")]
		[HideFoldout]
		public Cinemachine3OrbitRig.Settings Orbits = Cinemachine3OrbitRig.Settings.Default;

		[Tooltip("Defines the reference frame for horizontal recentering.  The axis center will be dynamically updated to be behind the selected object.")]
		public ReferenceFrames RecenteringTarget = ReferenceFrames.TrackingTarget;

		[Tooltip("Axis representing the current horizontal rotation.  Value is in degrees and represents a rotation about the up vector.")]
		public InputAxis HorizontalAxis = DefaultHorizontal;

		[Tooltip("Axis representing the current vertical rotation.  Value is in degrees and represents a rotation about the right vector.")]
		public InputAxis VerticalAxis = DefaultVertical;

		[Tooltip("Axis controlling the scale of the current distance.  Value is a scalar multiplier and is applied to the specified camera distance.")]
		public InputAxis RadialAxis = DefaultRadial;

		private Vector4 m_PreviousAxisValues;

		private Tracker m_TargetTracker;

		private Cinemachine3OrbitRig.OrbitSplineCache m_OrbitCache;

		private Action m_ResetHandler;

		internal Vector3 TrackedPoint { get; private set; }

		private static InputAxis DefaultHorizontal => new InputAxis
		{
			Value = 0f,
			Range = new Vector2(-180f, 180f),
			Wrap = true,
			Center = 0f,
			Recentering = InputAxis.RecenteringSettings.Default
		};

		private static InputAxis DefaultVertical => new InputAxis
		{
			Value = 17.5f,
			Range = new Vector2(-10f, 45f),
			Wrap = false,
			Center = 17.5f,
			Recentering = InputAxis.RecenteringSettings.Default
		};

		private static InputAxis DefaultRadial => new InputAxis
		{
			Value = 1f,
			Range = new Vector2(1f, 1f),
			Wrap = false,
			Center = 1f,
			Recentering = InputAxis.RecenteringSettings.Default
		};

		public override bool IsValid
		{
			get
			{
				if (base.enabled)
				{
					return base.FollowTarget != null;
				}
				return false;
			}
		}

		public override CinemachineCore.Stage Stage => CinemachineCore.Stage.Body;

		bool IInputAxisResetSource.HasResetHandler => m_ResetHandler != null;

		float CinemachineFreeLookModifier.IModifierValueSource.NormalizedModifierValue => GetCameraPoint(AxisValues).w / Mathf.Max(0.0001f, RadialAxis.Value);

		Vector3 CinemachineFreeLookModifier.IModifiablePositionDamping.PositionDamping
		{
			get
			{
				return TrackerSettings.PositionDamping;
			}
			set
			{
				TrackerSettings.PositionDamping = value;
			}
		}

		float CinemachineFreeLookModifier.IModifiableDistance.Distance
		{
			get
			{
				return Radius;
			}
			set
			{
				Radius = value;
			}
		}

		private Vector4 AxisValues => new Vector4(HorizontalAxis.Value, VerticalAxis.Value, RadialAxis.Value, VerticalAxis.GetNormalizedValue());

		private void OnValidate()
		{
			Radius = Mathf.Max(0f, Radius);
			TrackerSettings.Validate();
			HorizontalAxis.Validate();
			VerticalAxis.Validate();
			RadialAxis.Validate();
			RadialAxis.Range.x = Mathf.Max(RadialAxis.Range.x, 0.0001f);
			HorizontalAxis.Restrictions &= ~(InputAxis.RestrictionFlags.RangeIsDriven | InputAxis.RestrictionFlags.NoRecentering);
		}

		private void Reset()
		{
			TargetOffset = Vector3.zero;
			TrackerSettings = TrackerSettings.Default;
			OrbitStyle = OrbitStyles.Sphere;
			Radius = 5f;
			Orbits = Cinemachine3OrbitRig.Settings.Default;
			HorizontalAxis = DefaultHorizontal;
			VerticalAxis = DefaultVertical;
			RadialAxis = DefaultRadial;
		}

		public override float GetMaxDampTime()
		{
			return TrackerSettings.GetMaxDampTime();
		}

		void IInputAxisOwner.GetInputAxes(List<IInputAxisOwner.AxisDescriptor> axes)
		{
			axes.Add(new IInputAxisOwner.AxisDescriptor
			{
				DrivenAxis = () => ref HorizontalAxis,
				Name = "Look Orbit X",
				Hint = IInputAxisOwner.AxisDescriptor.Hints.X
			});
			axes.Add(new IInputAxisOwner.AxisDescriptor
			{
				DrivenAxis = () => ref VerticalAxis,
				Name = "Look Orbit Y",
				Hint = IInputAxisOwner.AxisDescriptor.Hints.Y
			});
			axes.Add(new IInputAxisOwner.AxisDescriptor
			{
				DrivenAxis = () => ref RadialAxis,
				Name = "Orbit Scale",
				Hint = IInputAxisOwner.AxisDescriptor.Hints.Y
			});
		}

		void IInputAxisResetSource.RegisterResetHandler(Action handler)
		{
			m_ResetHandler = (Action)Delegate.Combine(m_ResetHandler, handler);
		}

		void IInputAxisResetSource.UnregisterResetHandler(Action handler)
		{
			m_ResetHandler = (Action)Delegate.Remove(m_ResetHandler, handler);
		}

		internal Vector3 GetCameraOffsetForNormalizedAxisValue(float t)
		{
			return m_OrbitCache.SplineValue(Mathf.Clamp01((t + 1f) * 0.5f));
		}

		private Vector4 GetCameraPoint(Vector4 axisValues)
		{
			Vector3 vector2;
			float w;
			if (OrbitStyle == OrbitStyles.ThreeRing)
			{
				if (m_OrbitCache.SettingsChanged(in Orbits))
				{
					m_OrbitCache.UpdateOrbitCache(in Orbits);
				}
				Vector4 vector = m_OrbitCache.SplineValue(axisValues.w);
				vector *= axisValues.z;
				vector2 = Quaternion.AngleAxis(axisValues.x, Vector3.up) * vector;
				w = vector.w;
			}
			else
			{
				vector2 = Quaternion.Euler(axisValues.y, axisValues.x, 0f) * new Vector3(0f, 0f, (0f - Radius) * axisValues.z);
				w = axisValues.w * 2f - 1f;
			}
			if (TrackerSettings.BindingMode == BindingMode.LazyFollow)
			{
				vector2.z = 0f - Mathf.Abs(vector2.z);
			}
			return new Vector4(vector2.x, vector2.y, vector2.z, w);
		}

		public override bool OnTransitionFromCamera(ICinemachineCamera fromCam, Vector3 worldUp, float deltaTime)
		{
			m_ResetHandler?.Invoke();
			if (fromCam != null && (base.VirtualCamera.State.BlendHint & CameraState.BlendHints.InheritPosition) != CameraState.BlendHints.Nothing && !CinemachineCore.IsLiveInBlend(base.VirtualCamera))
			{
				CameraState state = fromCam.State;
				ForceCameraPosition(state.GetFinalPosition(), state.GetFinalOrientation());
				return true;
			}
			return false;
		}

		public override void ForceCameraPosition(Vector3 pos, Quaternion rot)
		{
			if (!(base.FollowTarget != null))
			{
				return;
			}
			CameraState newState = base.VcamState;
			newState.RawPosition = pos;
			newState.RawOrientation = rot;
			newState.PositionCorrection = Vector3.zero;
			newState.OrientationCorrection = Quaternion.identity;
			m_TargetTracker.OnForceCameraPosition(this, TrackerSettings.BindingMode, TargetOffset, ref newState);
			Vector3 dir = pos - m_TargetTracker.PreviousTargetPosition;
			float magnitude = dir.magnitude;
			if (magnitude > 0.001f)
			{
				dir /= magnitude;
				if (OrbitStyle == OrbitStyles.ThreeRing)
				{
					InferAxesFromPosition_ThreeRing(dir, magnitude, ref newState);
				}
				else
				{
					InferAxesFromPosition_Sphere(dir, magnitude, ref newState);
				}
				m_PreviousAxisValues = AxisValues;
			}
		}

		private void InferAxesFromPosition_Sphere(Vector3 dir, float distance, ref CameraState state)
		{
			Vector3 referenceUp = state.ReferenceUp;
			Vector3 v = Quaternion.Inverse(m_TargetTracker.GetReferenceOrientation(this, TrackerSettings.BindingMode, TargetOffset, referenceUp, ref state)) * dir;
			Vector3 eulerAngles = UnityVectorExtensions.SafeFromToRotation(Vector3.back, v, referenceUp).eulerAngles;
			VerticalAxis.Value = VerticalAxis.ClampValue(UnityVectorExtensions.NormalizeAngle(eulerAngles.x));
			HorizontalAxis.Value = HorizontalAxis.ClampValue(UnityVectorExtensions.NormalizeAngle(eulerAngles.y));
		}

		private void InferAxesFromPosition_ThreeRing(Vector3 dir, float distance, ref CameraState state)
		{
			Vector3 up = state.ReferenceUp;
			Quaternion orient = m_TargetTracker.GetReferenceOrientation(this, TrackerSettings.BindingMode, TargetOffset, up, ref state);
			HorizontalAxis.Value = GetHorizontalAxis();
			VerticalAxis.Value = GetVerticalAxisClosestValue(out var _);
			float GetHorizontalAxis()
			{
				Vector3 vector = (orient * Vector3.back).ProjectOntoPlane(up);
				if (!vector.AlmostZero())
				{
					return UnityVectorExtensions.SignedAngle(vector, dir.ProjectOntoPlane(up), up);
				}
				return HorizontalAxis.Value;
			}
			float GetVerticalAxisClosestValue(out Vector3 reference)
			{
				Vector3 vector = UnityVectorExtensions.SafeFromToRotation(up, Vector3.up, up) * dir;
				Vector3 vector2 = vector;
				vector2.y = 0f;
				if (!vector2.AlmostZero())
				{
					vector = Quaternion.AngleAxis(UnityVectorExtensions.SignedAngle(vector2, Vector3.back, Vector3.up), Vector3.up) * vector;
				}
				vector.x = 0f;
				vector.Normalize();
				float num = SteepestDescent(vector * distance);
				reference = m_OrbitCache.SplineValue(num);
				if (!(num <= 0.5f))
				{
					return Mathf.Lerp(VerticalAxis.Center, VerticalAxis.Range.y, MapTo(num, 0.5f, 1f));
				}
				return Mathf.Lerp(VerticalAxis.Range.x, VerticalAxis.Center, MapTo(num, 0f, 0.5f));
			}
			static float MapTo(float valueToMap, float fMin, float fMax)
			{
				return (valueToMap - fMin) / (fMax - fMin);
			}
			float SteepestDescent(Vector3 cameraOffset)
			{
				float num = InitialGuess();
				for (int i = 0; i < 5; i++)
				{
					float num2 = AngleFunction(num);
					float num3 = SlopeOfAngleFunction(num);
					if (Mathf.Abs(num3) < 0.005f || Mathf.Abs(num2) < 0.005f)
					{
						break;
					}
					num = Mathf.Clamp01(num - num2 / num3);
				}
				return num;
				float AngleFunction(float input)
				{
					Vector4 vector = m_OrbitCache.SplineValue(input);
					return Mathf.Abs(UnityVectorExtensions.SignedAngle(cameraOffset, vector, Vector3.right));
				}
				float InitialGuess()
				{
					if (m_OrbitCache.SettingsChanged(in Orbits))
					{
						m_OrbitCache.UpdateOrbitCache(in Orbits);
					}
					float best = 0.5f;
					float bestAngle = AngleFunction(best);
					for (int j = 0; j <= 5; j++)
					{
						float num4 = (float)j * 0.1f;
						ChooseBestAngle(0.5f + num4);
						ChooseBestAngle(0.5f - num4);
					}
					return best;
					void ChooseBestAngle(float x)
					{
						float num5 = AngleFunction(x);
						if (num5 < bestAngle)
						{
							bestAngle = num5;
							best = x;
						}
					}
				}
				float SlopeOfAngleFunction(float input)
				{
					float num4 = AngleFunction(input - 0.005f);
					return (AngleFunction(input + 0.005f) - num4) / 0.01f;
				}
			}
		}

		public override void OnTargetObjectWarped(Transform target, Vector3 positionDelta)
		{
			base.OnTargetObjectWarped(target, positionDelta);
			if (target == base.FollowTarget)
			{
				m_TargetTracker.OnTargetObjectWarped(positionDelta);
			}
		}

		public override void MutateCameraState(ref CameraState curState, float deltaTime)
		{
			m_TargetTracker.InitStateInfo(this, deltaTime, TrackerSettings.BindingMode, TargetOffset, curState.ReferenceUp);
			if (IsValid)
			{
				if (deltaTime < 0f && Application.isPlaying)
				{
					m_ResetHandler?.Invoke();
				}
				bool flag = HorizontalAxis.TrackValueChange();
				bool flag2 = VerticalAxis.TrackValueChange();
				bool flag3 = RadialAxis.TrackValueChange();
				Vector4 axisValues = AxisValues;
				Vector3 vector = GetCameraPoint(axisValues);
				m_TargetTracker.TrackTarget(this, deltaTime, curState.ReferenceUp, vector, in TrackerSettings, TargetOffset, ref curState, out var outTargetPosition, out var outTargetOrient);
				vector = outTargetOrient * vector;
				curState.ReferenceUp = outTargetOrient * Vector3.up;
				Vector3 followTargetPosition = base.FollowTargetPosition;
				TrackedPoint = outTargetPosition + m_TargetTracker.GetOffsetForMinimumTargetDistance(this, outTargetPosition, vector, curState.RawOrientation * Vector3.forward, curState.ReferenceUp, followTargetPosition);
				curState.RawPosition = outTargetPosition + vector;
				Vector3 vector2 = (curState.HasLookAt() ? (curState.ReferenceLookAt - (base.FollowTargetPosition + base.FollowTargetRotation * TargetOffset)) : Vector3.zero);
				vector -= vector2;
				Vector3 v = outTargetOrient * GetCameraPoint(m_PreviousAxisValues) - vector2;
				if (deltaTime >= 0f && base.VirtualCamera.PreviousStateIsValid && v.sqrMagnitude > 0.0001f && vector.sqrMagnitude > 0.0001f)
				{
					curState.RotationDampingBypass = UnityVectorExtensions.SafeFromToRotation(v, vector, curState.ReferenceUp);
				}
				if (TrackerSettings.BindingMode == BindingMode.LazyFollow)
				{
					HorizontalAxis.SetValueAndLastValue(0f);
					axisValues.x = 0f;
				}
				m_PreviousAxisValues = axisValues;
				if (HorizontalAxis.Recentering.Enabled)
				{
					UpdateHorizontalCenter(outTargetOrient);
				}
				flag |= flag2 && HorizontalAxis.Recentering.Time == VerticalAxis.Recentering.Time;
				flag |= flag3 && HorizontalAxis.Recentering.Time == RadialAxis.Recentering.Time;
				flag2 |= flag && VerticalAxis.Recentering.Time == HorizontalAxis.Recentering.Time;
				flag2 |= flag3 && VerticalAxis.Recentering.Time == RadialAxis.Recentering.Time;
				flag3 |= flag && RadialAxis.Recentering.Time == HorizontalAxis.Recentering.Time;
				flag3 |= flag2 && RadialAxis.Recentering.Time == VerticalAxis.Recentering.Time;
				if (Application.isPlaying)
				{
					HorizontalAxis.UpdateRecentering(deltaTime, flag);
					VerticalAxis.UpdateRecentering(deltaTime, flag2);
					RadialAxis.UpdateRecentering(deltaTime, flag3);
				}
			}
		}

		private void UpdateHorizontalCenter(Quaternion referenceOrientation)
		{
			Vector3 forward = Vector3.forward;
			switch (RecenteringTarget)
			{
			case ReferenceFrames.AxisCenter:
				if (TrackerSettings.BindingMode == BindingMode.LazyFollow)
				{
					HorizontalAxis.Center = 0f;
				}
				return;
			case ReferenceFrames.ParentObject:
				if (base.transform.parent != null)
				{
					forward = base.transform.parent.forward;
				}
				break;
			case ReferenceFrames.TrackingTarget:
				if (base.FollowTarget != null)
				{
					forward = base.FollowTarget.forward;
				}
				break;
			case ReferenceFrames.LookAtTarget:
				if (base.LookAtTarget != null)
				{
					forward = base.LookAtTarget.forward;
				}
				break;
			}
			Vector3 vector = referenceOrientation * Vector3.up;
			forward.ProjectOntoPlane(vector);
			HorizontalAxis.Center = 0f - Vector3.SignedAngle(forward, referenceOrientation * Vector3.forward, vector);
		}

		internal Quaternion GetReferenceOrientation()
		{
			return m_TargetTracker.PreviousReferenceOrientation.normalized;
		}
	}
}
