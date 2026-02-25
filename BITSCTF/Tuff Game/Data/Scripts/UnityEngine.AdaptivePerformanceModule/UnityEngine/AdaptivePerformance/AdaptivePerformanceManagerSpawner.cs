using System;
using System.Reflection;

namespace UnityEngine.AdaptivePerformance
{
	internal class AdaptivePerformanceManagerSpawner : ScriptableObject
	{
		public const string AdaptivePerformanceManagerObjectName = "AdaptivePerformanceManager";

		private GameObject m_ManagerGameObject;

		public GameObject ManagerGameObject => m_ManagerGameObject;

		private void OnEnable()
		{
			if (!(m_ManagerGameObject != null))
			{
				m_ManagerGameObject = GameObject.Find("AdaptivePerformanceManager");
			}
		}

		public void Initialize(bool isCheckingProvider)
		{
			if (m_ManagerGameObject != null)
			{
				return;
			}
			m_ManagerGameObject = new GameObject("AdaptivePerformanceManager");
			AdaptivePerformanceManager adaptivePerformanceManager = m_ManagerGameObject.AddComponent<AdaptivePerformanceManager>();
			if (isCheckingProvider && adaptivePerformanceManager.Indexer == null)
			{
				Deinitialize();
				return;
			}
			Holder.Instance = adaptivePerformanceManager;
			InstallScalers();
			Object.DontDestroyOnLoad(m_ManagerGameObject);
			IAdaptivePerformanceSettings settings = adaptivePerformanceManager.Settings;
			if (!(settings == null))
			{
				string[] availableScalerProfiles = settings.GetAvailableScalerProfiles();
				if (availableScalerProfiles.Length == 0)
				{
					APLog.Debug("No Scaler Profiles available. Did you remove all profiles manually from the provider Settings?");
				}
				else
				{
					settings.LoadScalerProfile(availableScalerProfiles[settings.defaultScalerProfilerIndex]);
				}
			}
		}

		public void Deinitialize()
		{
			if (!(m_ManagerGameObject == null))
			{
				Object.DestroyImmediate(m_ManagerGameObject);
				m_ManagerGameObject = null;
			}
		}

		private void InstallScalers()
		{
			Type typeFromHandle = typeof(AdaptivePerformanceScaler);
			Assembly[] assemblies = AppDomain.CurrentDomain.GetAssemblies();
			foreach (Assembly assembly in assemblies)
			{
				Type[] types = assembly.GetTypes();
				foreach (Type type in types)
				{
					if (typeFromHandle.IsAssignableFrom(type) && !type.IsAbstract)
					{
						ScriptableObject.CreateInstance(type);
					}
				}
			}
		}
	}
}
