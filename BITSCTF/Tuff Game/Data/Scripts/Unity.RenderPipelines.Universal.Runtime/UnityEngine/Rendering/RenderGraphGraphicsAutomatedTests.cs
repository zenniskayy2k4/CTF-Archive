using System;

namespace UnityEngine.Rendering
{
	public static class RenderGraphGraphicsAutomatedTests
	{
		private static bool activatedFromCommandLine => Array.Exists(Environment.GetCommandLineArgs(), (string arg) => arg == "-render-graph-reuse-tests");

		[Obsolete]
		public static bool enabled { get; set; } = activatedFromCommandLine;

		public static bool? forceRenderGraphState { get; set; } = activatedFromCommandLine ? new bool?(true) : ((bool?)null);
	}
}
