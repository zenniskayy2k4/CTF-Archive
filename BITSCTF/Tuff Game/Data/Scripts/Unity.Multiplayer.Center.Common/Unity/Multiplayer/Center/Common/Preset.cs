using System;
using UnityEngine;

namespace Unity.Multiplayer.Center.Common
{
	[Serializable]
	[InspectorOrder(InspectorSort.ByName, InspectorSortDirection.Ascending)]
	public enum Preset
	{
		[InspectorName("-")]
		None = 0,
		[InspectorName("Adventure")]
		Adventure = 1,
		[InspectorName("Shooter, Battle Royale, Battle Arena")]
		Shooter = 2,
		[InspectorName("Racing")]
		Racing = 3,
		[InspectorName("Card Battle, Turn-based, Tabletop")]
		TurnBased = 4,
		[InspectorName("Simulation")]
		Simulation = 5,
		[InspectorName("Strategy")]
		Strategy = 6,
		[InspectorName("Sports")]
		Sports = 7,
		[InspectorName("Role-Playing, MMO")]
		RolePlaying = 8,
		[InspectorName("Async, Idle, Hyper Casual, Puzzle")]
		Async = 9,
		[InspectorName("Fighting")]
		Fighting = 10,
		[InspectorName("Arcade, Platformer, Sandbox")]
		Sandbox = 11
	}
}
