using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Reflection;
using UnityEngine;
using UnityEngine.SceneManagement;

namespace Unity.VisualScripting
{
	[AddComponentMenu("Visual Scripting/Variables")]
	[DisableAnnotation]
	[IncludeInSettings(false)]
	public class Variables : LudiqBehaviour, IAotStubbable
	{
		[Serialize]
		[Inspectable]
		public VariableDeclarations declarations { get; internal set; } = new VariableDeclarations
		{
			Kind = VariableKind.Object
		};

		public static VariableDeclarations ActiveScene => Scene(SceneManager.GetActiveScene());

		public static VariableDeclarations Application => ApplicationVariables.current;

		public static VariableDeclarations Saved => SavedVariables.current;

		public static bool ExistInActiveScene => ExistInScene(SceneManager.GetActiveScene());

		public static VariableDeclarations Graph(GraphPointer pointer)
		{
			Ensure.That("pointer").IsNotNull(pointer);
			if (pointer.hasData)
			{
				return GraphInstance(pointer);
			}
			return GraphDefinition(pointer);
		}

		public static VariableDeclarations GraphInstance(GraphPointer pointer)
		{
			return pointer.GetGraphData<IGraphDataWithVariables>().variables;
		}

		public static VariableDeclarations GraphDefinition(GraphPointer pointer)
		{
			return GraphDefinition((IGraphWithVariables)pointer.graph);
		}

		public static VariableDeclarations GraphDefinition(IGraphWithVariables graph)
		{
			return graph.variables;
		}

		public static VariableDeclarations Object(GameObject go)
		{
			return go.GetOrAddComponent<Variables>().declarations;
		}

		public static VariableDeclarations Object(UnityEngine.Component component)
		{
			return Object(component.gameObject);
		}

		public static VariableDeclarations Scene(Scene? scene)
		{
			return SceneVariables.For(scene);
		}

		public static VariableDeclarations Scene(GameObject go)
		{
			return Scene(go.scene);
		}

		public static VariableDeclarations Scene(UnityEngine.Component component)
		{
			return Scene(component.gameObject);
		}

		public static bool ExistOnObject(GameObject go)
		{
			return go.GetComponent<Variables>() != null;
		}

		public static bool ExistOnObject(UnityEngine.Component component)
		{
			return ExistOnObject(component.gameObject);
		}

		public static bool ExistInScene(Scene? scene)
		{
			if (scene.HasValue)
			{
				return SceneVariables.InstantiatedIn(scene.Value);
			}
			return false;
		}

		[ContextMenu("Show Data...")]
		protected override void ShowData()
		{
			base.ShowData();
		}

		[EditorBrowsable(EditorBrowsableState.Never)]
		public IEnumerable<object> GetAotStubs(HashSet<object> visited)
		{
			foreach (VariableDeclaration declaration in declarations)
			{
				Type type = declaration.value?.GetType();
				if (!(type == null) && (string.IsNullOrEmpty(type.FullName) || (!type.FullName.Contains("UnityEngine.Audio.AudioMixer") && !type.FullName.Contains("UnityEditor.Audio.AudioMixerController"))))
				{
					ConstructorInfo publicDefaultConstructor = type.GetPublicDefaultConstructor();
					if (publicDefaultConstructor != null)
					{
						yield return publicDefaultConstructor;
					}
				}
			}
		}
	}
}
