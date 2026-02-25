using System;
using Unity.VisualScripting;
using UnityEngine;

internal class EventBusExamples
{
	public class CheatCodeController : MonoBehaviour
	{
		public const string CheatCodeActivated = "CheatCodeActivated";

		private static readonly KeyCode[] famousCheatCode = new KeyCode[10]
		{
			KeyCode.UpArrow,
			KeyCode.UpArrow,
			KeyCode.DownArrow,
			KeyCode.DownArrow,
			KeyCode.LeftArrow,
			KeyCode.RightArrow,
			KeyCode.LeftArrow,
			KeyCode.RightArrow,
			KeyCode.B,
			KeyCode.A
		};

		private int index;

		private EventHook cheatCodeHook;

		private Action<EmptyEventArgs> godModeDelegate;

		public GameObject player;

		private void Start()
		{
			cheatCodeHook = new EventHook("CheatCodeActivated");
			godModeDelegate = delegate
			{
				EnableGodMode();
			};
			EventBus.Register(cheatCodeHook, godModeDelegate);
		}

		private void Update()
		{
			if (Input.anyKeyDown)
			{
				if (Input.GetKeyDown(famousCheatCode[index]))
				{
					index++;
				}
				else
				{
					index = 0;
				}
				if (index >= famousCheatCode.Length)
				{
					EventBus.Trigger("CheatCodeActivated");
					EventBus.Trigger(new EventHook("CheatCodeActivated", player.GetComponent<ScriptMachine>()));
					index = 0;
				}
			}
		}

		private void OnDestroy()
		{
			EventBus.Unregister(cheatCodeHook, godModeDelegate);
		}

		private void EnableGodMode()
		{
			Debug.Log("Cheat code has been entered. Enabling god mode.");
		}
	}

	[UnitTitle("On Cheat Code Enabled")]
	public sealed class CheatCodeEnabled : MachineEventUnit<EmptyEventArgs>
	{
		protected override string hookName => "CheatCodeActivated";
	}
}
