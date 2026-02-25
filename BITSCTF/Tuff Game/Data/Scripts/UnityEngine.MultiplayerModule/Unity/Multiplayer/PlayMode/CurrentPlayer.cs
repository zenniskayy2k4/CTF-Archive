using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using UnityEngine;
using UnityEngine.Scripting.APIUpdating;

namespace Unity.Multiplayer.PlayMode
{
	[MovedFrom(true, "Unity.Multiplayer.Playmode", "Unity.Multiplayer.Playmode", null)]
	public static class CurrentPlayer
	{
		internal static Type s_EditorApiType = typeof(CurrentPlayerApi);

		private static CurrentPlayerApi s_CurrentPlayerApi;

		public static bool IsMainEditor
		{
			get
			{
				EnsureInitialized();
				return s_CurrentPlayerApi.IsMainEditor;
			}
		}

		public static IReadOnlyList<string> Tags
		{
			get
			{
				EnsureInitialized();
				return s_CurrentPlayerApi.ReadOnlyTags();
			}
		}

		private static void EnsureInitialized()
		{
			if (s_CurrentPlayerApi == null)
			{
				s_CurrentPlayerApi = new CurrentPlayerApi();
			}
		}

		[RuntimeInitializeOnLoadMethod(RuntimeInitializeLoadType.SubsystemRegistration)]
		private static void ReloadLatestTagsOnEnterPlaymode()
		{
			s_CurrentPlayerApi = null;
		}

		internal static void ReportResult(bool condition, string message = "", [CallerFilePath] string callingFilePath = "", [CallerLineNumber] int lineNumber = 0)
		{
			EnsureInitialized();
			s_CurrentPlayerApi.ReportResult(condition, message, callingFilePath, lineNumber);
		}

		[Obsolete("ReadOnlyTags has been deprecated. Use CurrentPlayer.Tags which has better performance properties.", false)]
		public static string[] ReadOnlyTags()
		{
			IReadOnlyList<string> tags = Tags;
			string[] array = new string[tags.Count];
			for (int i = 0; i < tags.Count; i++)
			{
				array[i] = tags[i];
			}
			return array;
		}
	}
}
